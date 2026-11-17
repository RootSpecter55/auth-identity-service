import type { Db } from '../../common/db';
import type { EmailTokenPurpose } from '../../generated/prisma/client';

/** Single-use, expiring tokens sent by email (verification and password reset). Stored hashed. */
export class EmailTokenRepository {
  create(
    db: Db,
    data: { userId: string; purpose: EmailTokenPurpose; tokenHash: string; expiresAt: Date },
  ) {
    return db.emailToken.create({ data });
  }

  findUsable(db: Db, tokenHash: string, purpose: EmailTokenPurpose, now: Date) {
    return db.emailToken.findFirst({
      where: { tokenHash, purpose, usedAt: null, expiresAt: { gt: now } },
    });
  }

  /** Compare-and-set, so two requests racing with one token cannot both use it. */
  async markUsed(db: Db, id: string, now: Date): Promise<boolean> {
    const { count } = await db.emailToken.updateMany({
      where: { id, usedAt: null },
      data: { usedAt: now },
    });
    return count === 1;
  }

  /** Invalidates every unused token of this purpose for the user (e.g. older reset links). */
  async expireAll(db: Db, userId: string, purpose: EmailTokenPurpose, now: Date): Promise<void> {
    await db.emailToken.updateMany({
      where: { userId, purpose, usedAt: null },
      data: { usedAt: now },
    });
  }
}
