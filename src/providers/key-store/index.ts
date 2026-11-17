import { KMSClient } from '@aws-sdk/client-kms';
import type { Config } from '../../common/config';
import type { KeyStore } from './key-store';
import { KmsKeyStore } from './kms.key-store';
import { LocalKeyStore } from './local.key-store';

export * from './key-store';

// Factory: picks where private keys live, so token signing does not care which store it is.
export function createKeyStore(config: Config): KeyStore {
  if (config.KEY_STORE === 'kms') {
    return new KmsKeyStore(new KMSClient({ region: config.AWS_REGION }));
  }
  return new LocalKeyStore(Buffer.from(config.KEY_ENCRYPTION_KEY, 'base64'));
}
