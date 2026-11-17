import { createPublicKey } from 'node:crypto';
import {
  CreateKeyCommand,
  GetPublicKeyCommand,
  SignCommand,
  type KMSClient,
} from '@aws-sdk/client-kms';
import type { KeyStore, PublicJwk } from './key-store';

/**
 * Converts a DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }), as KMS returns it, to the
 * fixed-size r || s form JWS uses. Each integer is left-padded or stripped to `size` bytes.
 */
export function derToJose(der: Buffer, size = 32): Buffer {
  let offset = 2; // SEQUENCE tag + length (P-256 signatures are always < 128 bytes)
  const readInteger = () => {
    if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
    const length = der[offset + 1]!;
    const value = der.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
    const trimmed = value.subarray(Math.max(0, value.length - size)); // drop a leading 0x00
    return Buffer.concat([Buffer.alloc(size - trimmed.length), trimmed]);
  };
  return Buffer.concat([readInteger(), readInteger()]);
}

/**
 * Keys held in AWS KMS (asymmetric ECC_NIST_P256, SIGN_VERIFY). The private key never leaves
 * KMS; privateKeyRef is the KMS key id. Written against the official SDK but not exercised by
 * the tests: it needs an AWS account, and creating a key creates a billable AWS resource.
 */
export class KmsKeyStore implements KeyStore {
  readonly name = 'kms' as const;

  constructor(private readonly kms: KMSClient) {}

  async createKey() {
    const created = await this.kms.send(
      new CreateKeyCommand({
        KeySpec: 'ECC_NIST_P256',
        KeyUsage: 'SIGN_VERIFY',
        Description: 'auth-identity-service JWT signing key',
      }),
    );
    const keyId = created.KeyMetadata?.KeyId;
    if (!keyId) throw new Error('KMS did not return a key id');

    const { PublicKey } = await this.kms.send(new GetPublicKeyCommand({ KeyId: keyId }));
    if (!PublicKey) throw new Error('KMS did not return a public key');
    const jwk = createPublicKey({
      key: Buffer.from(PublicKey),
      format: 'der',
      type: 'spki',
    }).export({
      format: 'jwk',
    });
    return {
      publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as PublicJwk,
      privateKeyRef: keyId,
    };
  }

  async sign(privateKeyRef: string, data: Buffer): Promise<Buffer> {
    const { Signature } = await this.kms.send(
      new SignCommand({
        KeyId: privateKeyRef,
        Message: data,
        MessageType: 'RAW', // KMS hashes with SHA-256 itself
        SigningAlgorithm: 'ECDSA_SHA_256',
      }),
    );
    if (!Signature) throw new Error('KMS did not return a signature');
    return derToJose(Buffer.from(Signature));
  }
}
