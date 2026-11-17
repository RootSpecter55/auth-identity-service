/** A P-256 public key as a JWK (kty, crv, x, y). */
export type PublicJwk = { kty: string; crv: string; x: string; y: string };

/**
 * Where the private half of a signing key lives. The signing_keys table keeps the public key
 * and an opaque `privateKeyRef` for every key, whichever store holds the private half.
 */
export interface KeyStore {
  readonly name: 'local' | 'kms';
  /** Creates a new ES256 (P-256) key pair. */
  createKey(): Promise<{ publicJwk: PublicJwk; privateKeyRef: string }>;
  /** Signs `data` with SHA-256 and returns the 64-byte JOSE signature (r || s). */
  sign(privateKeyRef: string, data: Buffer): Promise<Buffer>;
}
