import { createPrivateKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { decrypt, encrypt } from '../../common/crypto';
import type { KeyStore, PublicJwk } from './key-store';

/**
 * Keys generated in-process. The private key (PKCS#8 PEM) is encrypted with AES-256-GCM using
 * KEY_ENCRYPTION_KEY, and the ciphertext is the privateKeyRef stored in Postgres. A database
 * dump alone cannot sign tokens.
 */
export class LocalKeyStore implements KeyStore {
  readonly name = 'local' as const;
  private readonly decrypted = new Map<string, KeyObject>();

  constructor(private readonly encryptionKey: Buffer) {}

  async createKey() {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    return {
      publicJwk: { kty, crv, x, y } as PublicJwk,
      privateKeyRef: encrypt(pem, this.encryptionKey),
    };
  }

  async sign(privateKeyRef: string, data: Buffer): Promise<Buffer> {
    let key = this.decrypted.get(privateKeyRef);
    if (!key) {
      key = createPrivateKey(decrypt(privateKeyRef, this.encryptionKey));
      this.decrypted.set(privateKeyRef, key);
    }
    // JWS wants the raw r || s form, not the DER that crypto.sign produces by default.
    return sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
  }
}
