import { randomToken, sha256 } from '../../common/crypto';
import type { DbContext } from '../../common/db';
import { UnauthorizedError } from '../../common/errors';
import { hashPassword } from '../../common/passwords';
import type { EmailProvider } from '../../providers/email';
import type { EmailTokenRepository } from '../email-verification/email-tokens.repository';
import type { SessionRepository } from '../sessions/sessions.repository';
import type { UserRepository } from '../users/users.repository';
import type { ConfirmResetInput, RequestResetInput } from './password-reset.schemas';

const RESET_TTL_MINUTES = 30;
export const RESET_REQUESTED_MESSAGE =
  'If an account exists for this email, a reset link is on its way.';

export class PasswordResetService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly tokens: EmailTokenRepository,
    private readonly sessions: SessionRepository,
    private readonly email: EmailProvider,
    private readonly appUrl: string,
  ) {}

  /** The same answer whether or not the account exists. Each request invalidates older links. */
  async request({ email }: RequestResetInput) {
    const db = this.db.client();
    const user = await this.users.findByEmail(db, email);
    if (user && !user.disabledAt) {
      const token = randomToken();
      const now = new Date();
      await this.db.transaction(async (tx) => {
        await this.tokens.expireAll(tx, user.id, 'RESET_PASSWORD', now);
        await this.tokens.create(tx, {
          userId: user.id,
          purpose: 'RESET_PASSWORD',
          tokenHash: sha256(token),
          expiresAt: new Date(now.getTime() + RESET_TTL_MINUTES * 60 * 1000),
        });
      });
      await this.email.send({
        to: user.email,
        subject: 'Reset your password',
        text: `Reset your password: ${this.appUrl}/reset-password?token=${token}\nThe link expires in ${RESET_TTL_MINUTES} minutes. If you did not ask for this, ignore this email.`,
      });
    }
    return { message: RESET_REQUESTED_MESSAGE };
  }

  /** Sets the new password and signs the user out everywhere: whoever had access loses it. */
  async confirm({ token, newPassword }: ConfirmResetInput) {
    const passwordHash = await hashPassword(newPassword);
    const now = new Date();
    await this.db.transaction(async (tx) => {
      const row = await this.tokens.findUsable(tx, sha256(token), 'RESET_PASSWORD', now);
      if (!row || !(await this.tokens.markUsed(tx, row.id, now))) {
        throw new UnauthorizedError('Invalid or expired link');
      }
      await this.users.update(tx, row.userId, { passwordHash });
      await this.sessions.revokeAllForUser(tx, row.userId, 'PASSWORD_RESET');
    });
  }
}
