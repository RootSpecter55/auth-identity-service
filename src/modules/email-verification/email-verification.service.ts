import type { DbContext } from '../../common/db';
import { ConflictError, NotFoundError, UnauthorizedError } from '../../common/errors';
import { randomToken, sha256 } from '../../common/crypto';
import type { User } from '../../generated/prisma/client';
import type { EmailProvider } from '../../providers/email';
import type { UserRepository } from '../users/users.repository';
import type { EmailTokenRepository } from './email-tokens.repository';

const VERIFICATION_TTL_HOURS = 24;

export class EmailVerificationService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly tokens: EmailTokenRepository,
    private readonly email: EmailProvider,
    private readonly appUrl: string,
  ) {}

  /** Emails a single-use link. Only the token's hash is stored. */
  async send(user: Pick<User, 'id' | 'email'>) {
    const token = randomToken();
    await this.tokens.create(this.db.client(), {
      userId: user.id,
      purpose: 'VERIFY_EMAIL',
      tokenHash: sha256(token),
      expiresAt: new Date(Date.now() + VERIFICATION_TTL_HOURS * 60 * 60 * 1000),
    });
    await this.email.send({
      to: user.email,
      subject: 'Confirm your email address',
      text: `Confirm your email: ${this.appUrl}/verify-email?token=${token}\nThe link expires in ${VERIFICATION_TTL_HOURS} hours.`,
    });
  }

  async confirm(token: string) {
    const now = new Date();
    await this.db.transaction(async (tx) => {
      const row = await this.tokens.findUsable(tx, sha256(token), 'VERIFY_EMAIL', now);
      if (!row || !(await this.tokens.markUsed(tx, row.id, now))) {
        throw new UnauthorizedError('Invalid or expired link');
      }
      await this.users.update(tx, row.userId, { emailVerifiedAt: now });
    });
  }

  async resend(userId: string) {
    const user = await this.users.findById(this.db.client(), userId);
    if (!user) throw new NotFoundError('User');
    if (user.emailVerifiedAt) throw new ConflictError('Email is already verified');
    await this.send(user);
  }
}
