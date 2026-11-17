import { SendEmailCommand, type SESv2Client } from '@aws-sdk/client-sesv2';
import type { Email, EmailProvider } from './email-provider';

/** Amazon SES v2. Written against the official SDK but not exercised: it needs a verified sender. */
export class SesEmailProvider implements EmailProvider {
  constructor(
    private readonly ses: SESv2Client,
    private readonly from: string,
  ) {}

  async send({ to, subject, text }: Email): Promise<void> {
    await this.ses.send(
      new SendEmailCommand({
        FromEmailAddress: this.from,
        Destination: { ToAddresses: [to] },
        Content: { Simple: { Subject: { Data: subject }, Body: { Text: { Data: text } } } },
      }),
    );
  }
}
