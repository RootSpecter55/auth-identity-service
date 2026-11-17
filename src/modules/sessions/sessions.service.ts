import type { AuthUser } from '../../common/auth-middleware';
import { randomToken, sha256 } from '../../common/crypto';
import type { DbContext } from '../../common/db';
import { NotFoundError, UnauthorizedError } from '../../common/errors';
import { logger } from '../../common/logger';
import { toPage, toSkipTake } from '../../common/pagination';
import { dummyPasswordHash, verifyPassword } from '../../common/passwords';
import type { User } from '../../generated/prisma/client';
import type { MfaService } from '../mfa/mfa.service';
import type { TokensService } from '../tokens/tokens.service';
import type { UserRepository } from '../users/users.repository';
import type { LoginThrottle } from './login-throttle';
import type { RefreshTokenRepository, SessionRepository } from './sessions.repository';
import type { ListSessionsQuery, LoginInput, LoginMfaInput } from './sessions.schemas';

export type ClientInfo = { ipAddress: string | null; userAgent: string | null };

export type TokenPair = {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshToken: string;
  sessionId: string;
};

const INVALID_LOGIN = 'Invalid email or password';

export class SessionsService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly sessions: SessionRepository,
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly tokens: TokensService,
    private readonly mfa: MfaService,
    private readonly throttle: LoginThrottle,
    private readonly refreshTokenTtlDays: number,
  ) {}

  /**
   * Unknown email, wrong password and disabled account all get the same 401, after the same
   * argon2 work, and all count towards the same throttling. The response never says which.
   */
  async login(
    input: LoginInput,
    client: ClientInfo,
  ): Promise<TokenPair | { mfaRequired: true; mfaToken: string }> {
    const ip = client.ipAddress ?? 'unknown';
    await this.throttle.check(input.email, ip);

    const user = await this.users.findByEmail(this.db.client(), input.email);
    const passwordOk = await verifyPassword(
      user?.passwordHash ?? (await dummyPasswordHash()),
      input.password,
    );
    if (!user || !passwordOk || user.disabledAt) {
      await this.throttle.recordFailure(input.email, ip);
      throw new UnauthorizedError(INVALID_LOGIN);
    }
    await this.throttle.reset(input.email, ip);

    if (await this.mfa.isEnabled(user.id)) {
      return { mfaRequired: true, mfaToken: await this.mfa.createChallenge(user.id) };
    }
    return this.startSession(user, client);
  }

  /** Second login step for users with MFA. */
  async loginMfa(input: LoginMfaInput, client: ClientInfo): Promise<TokenPair> {
    const userId = await this.mfa.completeChallenge(input.mfaToken, input);
    const user = await this.users.findById(this.db.client(), userId);
    if (!user || user.disabledAt) throw new UnauthorizedError(INVALID_LOGIN);
    return this.startSession(user, client);
  }

  /**
   * Exchanges a refresh token for a new pair. The old refresh token stops working. If a token
   * that was already exchanged comes back, someone kept a copy: the whole session (every
   * token descended from that login) is revoked, and both holders have to log in again.
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    const db = this.db.client();
    const now = new Date();
    const row = await this.refreshTokens.findByHash(db, sha256(refreshToken));
    if (!row) throw new UnauthorizedError('Invalid refresh token');

    const { session } = row;
    if (row.status !== 'ACTIVE' || !(await this.refreshTokens.rotate(db, row.id, now))) {
      if (row.status === 'ROTATED' || row.status === 'ACTIVE') {
        // ACTIVE here means a concurrent request won the compare-and-set: also a reuse.
        await this.sessions.revoke(db, session.id, 'REFRESH_TOKEN_REUSE');
        logger.warn(
          { sessionId: session.id, userId: session.userId },
          'Refresh token reuse detected',
        );
      }
      throw new UnauthorizedError('Refresh token is no longer valid; the session was revoked');
    }
    if (session.revokedAt || session.expiresAt <= now || row.expiresAt <= now) {
      throw new UnauthorizedError('Session has ended');
    }
    const user = await this.users.findById(db, session.userId);
    if (!user || user.disabledAt) throw new UnauthorizedError('Session has ended');

    const next = randomToken();
    await this.db.transaction(async (tx) => {
      await this.refreshTokens.create(tx, {
        sessionId: session.id,
        tokenHash: sha256(next),
        expiresAt: session.expiresAt,
      });
      await this.sessions.touch(tx, session.id, now);
    });
    return this.tokenPair(user, session.id, next);
  }

  async logout(auth: AuthUser): Promise<void> {
    await this.sessions.revoke(this.db.client(), auth.sessionId, 'LOGOUT');
  }

  async list(auth: AuthUser, query: ListSessionsQuery) {
    const { items, total } = await this.sessions.list(this.db.client(), {
      where: { userId: auth.id, revokedAt: null, expiresAt: { gt: new Date() } },
      ...toSkipTake(query),
      orderBy: { lastUsedAt: 'desc' },
    });
    const views = items.map((session) => ({ ...session, current: session.id === auth.sessionId }));
    return toPage(views, total, query);
  }

  async revoke(auth: AuthUser, sessionId: string): Promise<void> {
    const session = await this.sessions.findById(this.db.client(), sessionId);
    if (!session || session.userId !== auth.id) throw new NotFoundError('Session');
    await this.sessions.revoke(this.db.client(), sessionId, 'REVOKED_BY_USER');
  }

  /**
   * Used by the auth middleware for this service's own endpoints: a valid signature is not
   * enough, the session must also still be live. So logout and revocation take effect here
   * immediately; other services rely on the short access-token lifetime.
   */
  resolveUser = async (accessToken: string): Promise<AuthUser> => {
    const claims = await this.tokens.verifyAccessToken(accessToken);
    const session = await this.sessions.findById(this.db.client(), claims.sid);
    if (!session || session.revokedAt || session.userId !== claims.sub) {
      throw new UnauthorizedError('Session has ended');
    }
    return { id: claims.sub, sessionId: claims.sid, roles: claims.roles };
  };

  private async startSession(user: User, client: ClientInfo): Promise<TokenPair> {
    const refreshToken = randomToken();
    const expiresAt = new Date(Date.now() + this.refreshTokenTtlDays * 24 * 60 * 60 * 1000);
    const session = await this.db.transaction(async (tx) => {
      const created = await this.sessions.create(tx, { userId: user.id, ...client, expiresAt });
      await this.refreshTokens.create(tx, {
        sessionId: created.id,
        tokenHash: sha256(refreshToken),
        expiresAt,
      });
      return created;
    });
    return this.tokenPair(user, session.id, refreshToken);
  }

  private async tokenPair(user: User, sessionId: string, refreshToken: string): Promise<TokenPair> {
    const roles = await this.users.roleNames(this.db.client(), user.id);
    const { token, expiresIn } = await this.tokens.issueAccessToken({
      sub: user.id,
      sid: sessionId,
      roles,
      email_verified: user.emailVerifiedAt !== null,
    });
    return { accessToken: token, tokenType: 'Bearer', expiresIn, refreshToken, sessionId };
  }
}
