import type { DbContext } from '../../common/db';
import { ConflictError } from '../../common/errors';
import { toPage, toSkipTake } from '../../common/pagination';
import type { RoleRepository } from './roles.repository';
import type { CreateRoleInput, ListRolesQuery } from './roles.schemas';

export class RolesService {
  constructor(
    private readonly db: DbContext,
    private readonly roles: RoleRepository,
  ) {}

  async list(query: ListRolesQuery) {
    const { items, total } = await this.roles.list(this.db.client(), {
      ...toSkipTake(query),
      orderBy: { name: 'asc' },
    });
    return toPage(items, total, query);
  }

  async create(input: CreateRoleInput) {
    const db = this.db.client();
    if (await this.roles.findByName(db, input.name)) {
      throw new ConflictError(`Role ${input.name} already exists`);
    }
    return this.roles.create(db, input);
  }
}
