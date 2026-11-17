import { BaseRepository } from '../../common/base-repository';
import type { Db } from '../../common/db';
import type { Prisma, SigningKey } from '../../generated/prisma/client';

export class SigningKeyRepository extends BaseRepository<
  SigningKey,
  Prisma.SigningKeyUncheckedCreateInput,
  Prisma.SigningKeyUncheckedUpdateInput,
  Prisma.SigningKeyWhereInput
> {
  protected delegate(db: Db) {
    return db.signingKey;
  }

  findActive(db: Db) {
    return db.signingKey.findFirst({ where: { status: 'ACTIVE' } });
  }

  findNext(db: Db) {
    return db.signingKey.findFirst({ where: { status: 'NEXT' } });
  }

  /** The keys that belong in the JWKS: next, active, and retired ones still in their window. */
  findPublished(db: Db, now: Date) {
    return db.signingKey.findMany({
      where: {
        OR: [
          { status: { in: ['NEXT', 'ACTIVE'] } },
          { status: 'RETIRED', publishUntil: { gt: now } },
        ],
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async promote(db: Db, id: string): Promise<void> {
    await db.signingKey.update({ where: { id }, data: { status: 'ACTIVE' } });
  }

  async retire(db: Db, id: string, retiredAt: Date, publishUntil: Date): Promise<void> {
    await db.signingKey.update({
      where: { id },
      data: { status: 'RETIRED', retiredAt, publishUntil },
    });
  }
}
