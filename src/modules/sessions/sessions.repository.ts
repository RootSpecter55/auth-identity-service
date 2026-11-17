import { BaseRepository } from '../../common/base-repository';
import type { Db } from '../../common/db';
import type { Prisma, Session } from '../../generated/prisma/client';

export class SessionRepository extends BaseRepository<
  Session,
  Prisma.SessionUncheckedCreateInput,
  Prisma.SessionUncheckedUpdateInput,
  Prisma.SessionWhereInput
> {
  protected delegate(db: Db) {
    return db.session;
  }

  /** Revokes the session and every refresh token in its family. */
  async revoke(db: Db, sessionId: string, reason: string): Promise<void> {
    await db.session.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason },
    });
    await db.refreshToken.updateMany({
      where: { sessionId, status: { not: 'REVOKED' } },
      data: { status: 'REVOKED' },
    });
  }

  /** Signs a user out everywhere, optionally keeping one session (the one making the change). */
  async revokeAllForUser(db: Db, userId: string, reason: string, exceptSessionId?: string) {
    const sessions = await db.session.findMany({
      where: {
        userId,
        revokedAt: null,
        ...(exceptSessionId ? { id: { not: exceptSessionId } } : {}),
      },
      select: { id: true },
    });
    for (const { id } of sessions) await this.revoke(db, id, reason);
  }

  async touch(db: Db, sessionId: string, now: Date): Promise<void> {
    await db.session.update({ where: { id: sessionId }, data: { lastUsedAt: now } });
  }
}

export class RefreshTokenRepository {
  create(db: Db, data: { sessionId: string; tokenHash: string; expiresAt: Date }) {
    return db.refreshToken.create({ data });
  }

  findByHash(db: Db, tokenHash: string) {
    return db.refreshToken.findUnique({ where: { tokenHash }, include: { session: true } });
  }

  /**
   * Marks the token used, only if it is still ACTIVE (compare-and-set). False means another
   * request used it first, which is treated exactly like reuse.
   */
  async rotate(db: Db, id: string, now: Date): Promise<boolean> {
    const { count } = await db.refreshToken.updateMany({
      where: { id, status: 'ACTIVE' },
      data: { status: 'ROTATED', usedAt: now },
    });
    return count === 1;
  }
}
