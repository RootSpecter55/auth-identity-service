import type { AuthUser } from '../../common/auth-middleware';
import type { DbContext } from '../../common/db';
import { NotFoundError, UnauthorizedError } from '../../common/errors';
import { hashPassword, verifyPassword } from '../../common/passwords';
import type { EmailProvider } from '../../providers/email';
import type { EmailVerificationService } from '../email-verification/email-verification.service';
import type { RoleRepository } from '../roles/roles.repository';
import type { SessionRepository } from '../sessions/sessions.repository';
import { toUserView, type UserRepository } from './users.repository';
import type { ChangePasswordInput, RegisterInput, UpdateMeInput } from './users.schemas';

export const REGISTERED_MESSAGE = 'If this email can be registered, we have sent a link to it.';

export class UsersService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly roles: RoleRepository,
    private readonly sessions: SessionRepository,
    private readonly verification: EmailVerificationService,
    private readonly email: EmailProvider,
  ) {}

  /**
   * Always gives the same answer, so registration cannot be used to find out which emails have
   * accounts. An existing account gets an email saying someone tried to register with it. The
   * password is hashed in both cases, so the response time is the same too.
   */
  async register(input: RegisterInput) {
    const passwordHash = await hashPassword(input.password);
    const existing = await this.users.findByEmail(this.db.client(), input.email);

    if (existing) {
      await this.email.send({
        to: existing.email,
        subject: 'Someone tried to register with your email',
        text: 'Somebody tried to create an account with this address. If it was you, sign in or reset your password instead. Otherwise you can ignore this email.',
      });
      return { message: REGISTERED_MESSAGE };
    }

    const user = await this.db.transaction(async (tx) => {
      const created = await this.users.create(tx, {
        email: input.email,
        name: input.name,
        passwordHash,
      });
      await this.roles.grant(tx, created.id, 'user');
      return created;
    });
    await this.verification.send(user);
    return { message: REGISTERED_MESSAGE };
  }

  async me(userId: string) {
    const db = this.db.client();
    const user = await this.users.findById(db, userId);
    if (!user) throw new NotFoundError('User');
    return toUserView(user, await this.users.roleNames(db, userId));
  }

  async updateMe(userId: string, input: UpdateMeInput) {
    await this.users.update(this.db.client(), userId, input);
    return this.me(userId);
  }

  /** Requires the current password. Signs out every other session, keeping this one. */
  async changePassword(auth: AuthUser, input: ChangePasswordInput) {
    const user = await this.users.findById(this.db.client(), auth.id);
    if (!user || !(await verifyPassword(user.passwordHash, input.currentPassword))) {
      throw new UnauthorizedError('Current password is incorrect');
    }
    const passwordHash = await hashPassword(input.newPassword);
    await this.db.transaction(async (tx) => {
      await this.users.update(tx, auth.id, { passwordHash });
      await this.sessions.revokeAllForUser(tx, auth.id, 'PASSWORD_CHANGED', auth.sessionId);
    });
  }
}
