import type { Db } from '../../common/db';
import type { Email, EmailProvider } from './email-provider';

/** Local stand-in: "sends" by storing the email in dev_emails, readable via GET /dev/emails. */
export class FakeEmailProvider implements EmailProvider {
  constructor(private readonly db: () => Db) {}

  async send(email: Email): Promise<void> {
    await this.db().devEmail.create({ data: email });
  }
}
