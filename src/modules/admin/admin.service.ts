import type { AuthUser } from '../../common/auth-middleware';
import type { DbContext } from '../../common/db';
import { ConflictError, NotFoundError } from '../../common/errors';
import { toPage, toSkipTake, type PaginationQuery } from '../../common/pagination';
import type { RoleRepository } from '../roles/roles.repository';
import type { SessionRepository } from '../sessions/sessions.repository';
import type { TokensService } from '../tokens/tokens.service';
import { toUserView, type UserRepository } from '../users/users.repository';
import type { ListUsersQuery } from './admin.schemas';

/** Role changes show up in a user's access token at their next refresh. */
export class AdminService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly roles: RoleRepository,
    private readonly sessions: SessionRepository,
    private readonly tokens: TokensService,
  ) {}

  async listUsers(query: ListUsersQuery) {
    const db = this.db.client();
    const { items, total } = await this.users.list(db, {
      where: query.email ? { email: { contains: query.email.toLowerCase() } } : {},
      ...toSkipTake(query),
      orderBy: { createdAt: 'desc' },
    });
    const views = await Promise.all(
      items.map(async (u) => toUserView(u, await this.users.roleNames(db, u.id))),
    );
    return toPage(views, total, query);
  }

  private async load(userId: string) {
    const user = await this.users.findById(this.db.client(), userId);
    if (!user) throw new NotFoundError('User');
    return user;
  }

  async grantRole(userId: string, role: string) {
    await this.load(userId);
    await this.roles.grant(this.db.client(), userId, role);
    return { roles: await this.users.roleNames(this.db.client(), userId) };
  }

  /** An admin cannot remove their own admin role, so the last admin cannot lock everyone out. */
  async revokeRole(actor: AuthUser, userId: string, role: string) {
    if (actor.id === userId && role === 'admin') {
      throw new ConflictError('You cannot remove your own admin role');
    }
    await this.load(userId);
    await this.roles.revoke(this.db.client(), userId, role);
    return { roles: await this.users.roleNames(this.db.client(), userId) };
  }

  /** Disabling signs the user out everywhere; logins and refreshes are refused until enabled. */
  async disable(actor: AuthUser, userId: string) {
    if (actor.id === userId) throw new ConflictError('You cannot disable yourself');
    await this.load(userId);
    await this.db.transaction(async (tx) => {
      await this.users.update(tx, userId, { disabledAt: new Date() });
      await this.sessions.revokeAllForUser(tx, userId, 'USER_DISABLED');
    });
  }

  async enable(userId: string) {
    await this.load(userId);
    await this.users.update(this.db.client(), userId, { disabledAt: null });
  }

  listKeys(query: PaginationQuery) {
    return this.tokens.listKeys(query);
  }

  rotateKey() {
    return this.tokens.rotate();
  }
}
