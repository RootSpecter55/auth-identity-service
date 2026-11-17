import { BaseRepository } from '../../common/base-repository';
import type { Db } from '../../common/db';
import type { DevEmail, Prisma } from '../../generated/prisma/client';

export class DevEmailRepository extends BaseRepository<
  DevEmail,
  Prisma.DevEmailUncheckedCreateInput,
  Prisma.DevEmailUncheckedUpdateInput,
  Prisma.DevEmailWhereInput
> {
  protected delegate(db: Db) {
    return db.devEmail;
  }
}
