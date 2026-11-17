import { SESv2Client } from '@aws-sdk/client-sesv2';
import type { Config } from '../../common/config';
import { getPrisma } from '../../common/db';
import type { EmailProvider } from './email-provider';
import { FakeEmailProvider } from './fake.provider';
import { SesEmailProvider } from './ses.provider';

export * from './email-provider';

// Factory: picks the email transport from config, so modules only see EmailProvider.
export function createEmailProvider(config: Config): EmailProvider {
  if (config.EMAIL_PROVIDER === 'ses') {
    return new SesEmailProvider(new SESv2Client({ region: config.AWS_REGION }), config.EMAIL_FROM);
  }
  return new FakeEmailProvider(getPrisma);
}
