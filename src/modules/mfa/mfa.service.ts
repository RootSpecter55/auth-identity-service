import { randomBytes } from 'node:crypto';
import type { DbContext } from '../../common/db';
import { ConflictError, UnauthorizedError } from '../../common/errors';
import { decrypt, encrypt, randomToken, sha256 } from '../../common/crypto';
import type { UserRepository } from '../users/users.repository';
import type {
  MfaChallengeRepository,
  RecoveryCodeRepository,
  TotpRepository,
} from './mfa.repository';
import { base32Encode, generateTotpSecret, matchTotp, otpauthUri } from './totp';

const RECOVERY_CODE_COUNT = 10;
const CHALLENGE_TTL_SECONDS = 300;
const CHALLENGE_MAX_ATTEMPTS = 5;

/** "abcd-efgh-ijkl": 60 random bits, easy to type. Compared case- and dash-insensitively. */
function newRecoveryCode(): string {
  return base32Encode(randomBytes(8))
    .slice(0, 12)
    .toLowerCase()
    .replace(/(.{4})(?!$)/g, '$1-');
}

function normaliseRecoveryCode(code: string): string {
  return code.replace(/[\s-]/g, '').toLowerCase();
}

export class MfaService {
  constructor(
    private readonly db: DbContext,
    private readonly users: UserRepository,
    private readonly totp: TotpRepository,
    private readonly recoveryCodes: RecoveryCodeRepository,
    private readonly challenges: MfaChallengeRepository,
    private readonly encryptionKey: Buffer,
    private readonly issuerName: string,
  ) {}

  async isEnabled(userId: string): Promise<boolean> {
    const factor = await this.totp.findByUser(this.db.client(), userId);
    return factor?.status === 'ACTIVE';
  }

  /** Step 1: a new secret for the authenticator app. Not active until a code proves it works. */
  async enroll(userId: string) {
    const db = this.db.client();
    if (await this.isEnabled(userId)) throw new ConflictError('MFA is already enabled');
    const user = await this.users.findById(db, userId);
    const secret = generateTotpSecret();
    await this.totp.upsertPending(db, userId, encrypt(secret, this.encryptionKey));
    return { secret, otpauthUri: otpauthUri(secret, user!.email, this.issuerName) };
  }

  /** Step 2: a correct code switches MFA on and returns the recovery codes, once. */
  async activate(userId: string, code: string) {
    const factor = await this.totp.findByUser(this.db.client(), userId);
    if (factor?.status !== 'PENDING') throw new ConflictError('Start enrolment first');
    const step = matchTotp(decrypt(factor.secretEncrypted, this.encryptionKey), code);
    if (step === null) throw new UnauthorizedError('Invalid code');

    return this.db.transaction(async (tx) => {
      await this.totp.activate(tx, userId, step, new Date());
      return { recoveryCodes: await this.issueRecoveryCodes(tx, userId) };
    });
  }

  async disable(userId: string, code: string) {
    await this.requireCurrentCode(userId, code);
    await this.db.transaction(async (tx) => {
      await this.totp.delete(tx, userId);
      await this.recoveryCodes.deleteAll(tx, userId);
    });
  }

  async regenerateRecoveryCodes(userId: string, code: string) {
    await this.requireCurrentCode(userId, code);
    return { recoveryCodes: await this.issueRecoveryCodes(this.db.client(), userId) };
  }

  /** After a correct password: a short-lived token for the second step of the login. */
  async createChallenge(userId: string): Promise<string> {
    const token = randomToken();
    await this.challenges.create(this.db.client(), {
      userId,
      tokenHash: sha256(token),
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000),
    });
    return token;
  }

  /**
   * The second login step. A challenge allows a few attempts, so the 6-digit code cannot be
   * brute-forced through one password check. Returns the user id on success.
   */
  async completeChallenge(
    mfaToken: string,
    proof: { code?: string; recoveryCode?: string },
  ): Promise<string> {
    const db = this.db.client();
    const challenge = await this.challenges.findByHash(db, sha256(mfaToken));
    const invalid = new UnauthorizedError('Invalid or expired MFA challenge');
    if (!challenge || challenge.usedAt || challenge.expiresAt <= new Date()) throw invalid;
    if ((await this.challenges.addAttempt(db, challenge.id)) > CHALLENGE_MAX_ATTEMPTS)
      throw invalid;

    const ok = proof.code
      ? await this.consumeCode(challenge.userId, proof.code)
      : await this.consumeRecoveryCode(challenge.userId, proof.recoveryCode ?? '');
    if (!ok) throw new UnauthorizedError('Invalid code');
    if (!(await this.challenges.markUsed(db, challenge.id, new Date()))) throw invalid;
    return challenge.userId;
  }

  /** True if `code` is valid now and has not been used before. Each code works once. */
  private async consumeCode(userId: string, code: string): Promise<boolean> {
    const db = this.db.client();
    const factor = await this.totp.findByUser(db, userId);
    if (factor?.status !== 'ACTIVE') return false;
    const step = matchTotp(decrypt(factor.secretEncrypted, this.encryptionKey), code);
    return step !== null && (await this.totp.consumeStep(db, userId, step));
  }

  private async consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    const db = this.db.client();
    const row = await this.recoveryCodes.findUnused(
      db,
      userId,
      sha256(normaliseRecoveryCode(code)),
    );
    return row !== null && (await this.recoveryCodes.markUsed(db, row.id, new Date()));
  }

  private async requireCurrentCode(userId: string, code: string) {
    if (!(await this.isEnabled(userId))) throw new ConflictError('MFA is not enabled');
    if (!(await this.consumeCode(userId, code))) throw new UnauthorizedError('Invalid code');
  }

  private async issueRecoveryCodes(
    db: Parameters<RecoveryCodeRepository['replaceAll']>[0],
    userId: string,
  ) {
    const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
    await this.recoveryCodes.replaceAll(
      db,
      userId,
      codes.map((c) => sha256(normaliseRecoveryCode(c))),
    );
    return codes;
  }
}
