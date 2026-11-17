import type { DbContext } from '../../common/db';
import { toPage, toSkipTake } from '../../common/pagination';
import type { DevEmailRepository } from './dev-emails.repository';
import type { ListDevEmailsQuery } from './dev-emails.schemas';

/** Reads what the fake email provider "sent". Mounted only when DEV_ENDPOINTS=true. */
export class DevEmailsService {
  constructor(
    private readonly db: DbContext,
    private readonly emails: DevEmailRepository,
  ) {}

  async list(query: ListDevEmailsQuery) {
    const { items, total } = await this.emails.list(this.db.client(), {
      where: query.to ? { to: query.to } : {},
      ...toSkipTake(query),
      orderBy: { createdAt: 'desc' },
    });
    return toPage(items, total, query);
  }
}
