import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

/** A random token for links, refresh tokens and challenges: 256 bits, URL-safe. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * SHA-256, hex. Used for tokens, which are long and random: a fast hash is enough because
 * they cannot be guessed, and a lookup by hash needs a deterministic one. Passwords use argon2.
 */
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * AES-256-GCM with a random 96-bit IV. Output: "v1.<iv>.<tag>.<ciphertext>", base64url parts.
 * GCM authenticates the data, so a modified ciphertext fails to decrypt instead of decrypting
 * to garbage.
 */
export function encrypt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv, cipher.getAuthTag(), ciphertext]
    .map((p) => (typeof p === 'string' ? p : p.toString('base64url')))
    .join('.');
}

export function decrypt(encoded: string, key: Buffer): string {
  const [version, iv, tag, ciphertext] = encoded.split('.');
  if (version !== 'v1' || !iv || !tag || ciphertext === undefined) {
    throw new Error('Unrecognised encrypted value');
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}
