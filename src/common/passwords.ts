import { Algorithm, hash, verify } from '@node-rs/argon2';

/** argon2id with the OWASP minimum: 19 MiB memory, 2 iterations, 1 lane. */
const OPTIONS = { algorithm: Algorithm.Argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 };

export function hashPassword(password: string): Promise<string> {
  return hash(password, OPTIONS);
}

export function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  return verify(passwordHash, password);
}

/**
 * Checking a login for an unknown email still runs one argon2 verification, against this hash,
 * so the response takes as long as for a real account and timing does not reveal which emails
 * exist.
 */
let dummyHash: Promise<string> | undefined;
export function dummyPasswordHash(): Promise<string> {
  dummyHash ??= hashPassword('not-a-real-password-just-for-timing');
  return dummyHash;
}
