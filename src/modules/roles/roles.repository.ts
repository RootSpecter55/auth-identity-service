import { BaseRepository } from '../../common/base-repository';
import type { Db } from '../../common/db';
import { NotFoundError } from '../../common/errors';
import type { Prisma, Role } from '../../generated/prisma/client';

export class RoleRepository extends BaseRepository<
  Role,
  Prisma.RoleUncheckedCreateInput,
  Prisma.RoleUncheckedUpdateInput,
  Prisma.RoleWhereInput
> {
  protected delegate(db: Db) {
    return db.role;
  }

  findByName(db: Db, name: string) {
    return db.role.findUnique({ where: { name } });
  }

  /** Idempotent: granting a role the user already has does nothing. */
  async grant(db: Db, userId: string, roleName: string): Promise<void> {
    const role = await this.findByName(db, roleName);
    if (!role) throw new NotFoundError(`Role ${roleName}`);
    await db.userRole.upsert({
      where: { userId_roleId: { userId, roleId: role.id } },
      update: {},
      create: { userId, roleId: role.id },
    });
  }

  async revoke(db: Db, userId: string, roleName: string): Promise<void> {
    await db.userRole.deleteMany({ where: { userId, role: { name: roleName } } });
  }
}
