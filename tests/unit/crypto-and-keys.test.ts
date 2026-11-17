import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { decrypt, encrypt, sha256 } from '../../src/common/crypto';
import { derToJose } from '../../src/providers/key-store/kms.key-store';
import { LocalKeyStore } from '../../src/providers/key-store/local.key-store';

const key = Buffer.alloc(32, 7);

describe('AES-256-GCM helpers', () => {
  it('round-trips, with a fresh IV each time', () => {
    const a = encrypt('secret', key);
    const b = encrypt('secret', key);
    expect(a).not.toBe(b);
    expect(decrypt(a, key)).toBe('secret');
  });

  it('refuses a modified ciphertext or the wrong key', () => {
    const encrypted = encrypt('secret', key);
    const parts = encrypted.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    expect(() => decrypt(parts.join('.'), key)).toThrow();
    expect(() => decrypt(encrypted, Buffer.alloc(32, 8))).toThrow();
  });

  it('hashes tokens with SHA-256', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('LocalKeyStore', () => {
  it('creates encrypted P-256 keys whose signatures verify against the public JWK', async () => {
    const store = new LocalKeyStore(key);
    const { publicJwk, privateKeyRef } = await store.createKey();
    expect(publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(privateKeyRef).not.toContain('PRIVATE KEY');

    const data = Buffer.from('header.payload');
    const signature = await store.sign(privateKeyRef, data);
    expect(signature).toHaveLength(64);
    const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
    expect(verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)).toBe(
      true,
    );
  });
});

describe('derToJose (KMS signature conversion)', () => {
  it('turns DER ECDSA signatures into 64-byte r||s that verify', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    for (let i = 0; i < 50; i++) {
      // Different messages give r and s with and without the DER leading-zero byte.
      const data = Buffer.from(`message ${i}`);
      const der = sign('sha256', data, { key: privateKey, dsaEncoding: 'der' });
      const jose = derToJose(der);
      expect(jose).toHaveLength(64);
      expect(verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, jose)).toBe(
        true,
      );
    }
  });
});
