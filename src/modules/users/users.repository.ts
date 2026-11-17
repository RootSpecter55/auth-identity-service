import { BaseRepository } from '../../common/base-repository';
import type { Db } from '../../common/db';
import type { Prisma, User } from '../../generated/prisma/client';

export class UserRepository extends BaseRepository<
  User,
  Prisma.UserUncheckedCreateInput,
  Prisma.UserUncheckedUpdateInput,
  Prisma.UserWhereInput
> {
  protected delegate(db: Db) {
    return db.user;
  }

  findByEmail(db: Db, email: string) {
    return db.user.findUnique({ where: { email } });
  }

  async roleNames(db: Db, userId: string): Promise<string[]> {
    const rows = await db.userRole.findMany({
      where: { userId },
      include: { role: true },
      orderBy: { role: { name: 'asc' } },
    });
    return rows.map((row) => row.role.name);
  }
}

/** The public shape of a user: never the password hash. */
export function toUserView(user: User, roles: string[]) {
  const { passwordHash: _omit, ...rest } = user;
  return { ...rest, roles };
}
