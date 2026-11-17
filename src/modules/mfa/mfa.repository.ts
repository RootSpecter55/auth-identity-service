import type { Db } from '../../common/db';

export class TotpRepository {
  findByUser(db: Db, userId: string) {
    return db.totpFactor.findUnique({ where: { userId } });
  }

  /** Starts (or restarts) enrolment with a new secret. */
  upsertPending(db: Db, userId: string, secretEncrypted: string) {
    return db.totpFactor.upsert({
      where: { userId },
      update: { secretEncrypted, status: 'PENDING', lastUsedStep: null, activatedAt: null },
      create: { userId, secretEncrypted },
    });
  }

  async activate(db: Db, userId: string, step: number, now: Date): Promise<void> {
    await db.totpFactor.update({
      where: { userId },
      data: { status: 'ACTIVE', activatedAt: now, lastUsedStep: step },
    });
  }

  /**
   * Records `step` as used, but only if it is later than the last one used. False means the
   * code was already used (or a later one was), so it is a replay.
   */
  async consumeStep(db: Db, userId: string, step: number): Promise<boolean> {
    const { count } = await db.totpFactor.updateMany({
      where: { userId, OR: [{ lastUsedStep: null }, { lastUsedStep: { lt: step } }] },
      data: { lastUsedStep: step },
    });
    return count === 1;
  }

  async delete(db: Db, userId: string): Promise<void> {
    await db.totpFactor.deleteMany({ where: { userId } });
  }
}

export class RecoveryCodeRepository {
  async replaceAll(db: Db, userId: string, codeHashes: string[]): Promise<void> {
    await db.recoveryCode.deleteMany({ where: { userId } });
    await db.recoveryCode.createMany({
      data: codeHashes.map((codeHash) => ({ userId, codeHash })),
    });
  }

  findUnused(db: Db, userId: string, codeHash: string) {
    return db.recoveryCode.findFirst({ where: { userId, codeHash, usedAt: null } });
  }

  async markUsed(db: Db, id: string, now: Date): Promise<boolean> {
    const { count } = await db.recoveryCode.updateMany({
      where: { id, usedAt: null },
      data: { usedAt: now },
    });
    return count === 1;
  }

  async deleteAll(db: Db, userId: string): Promise<void> {
    await db.recoveryCode.deleteMany({ where: { userId } });
  }
}

export class MfaChallengeRepository {
  create(db: Db, data: { userId: string; tokenHash: string; expiresAt: Date }) {
    return db.mfaChallenge.create({ data });
  }

  findByHash(db: Db, tokenHash: string) {
    return db.mfaChallenge.findUnique({ where: { tokenHash } });
  }

  /** Counts an attempt and returns the new count (atomic, so parallel guesses are all counted). */
  async addAttempt(db: Db, id: string): Promise<number> {
    const row = await db.mfaChallenge.update({
      where: { id },
      data: { attempts: { increment: 1 } },
    });
    return row.attempts;
  }

  async markUsed(db: Db, id: string, now: Date): Promise<boolean> {
    const { count } = await db.mfaChallenge.updateMany({
      where: { id, usedAt: null },
      data: { usedAt: now },
    });
    return count === 1;
  }
}
