import type { Request, Response } from 'express';
import { sendPage } from '../../common/response';
import type { ListDevEmailsQuery } from './dev-emails.schemas';
import type { DevEmailsService } from './dev-emails.service';

export class DevEmailsController {
  constructor(private readonly service: DevEmailsService) {}

  list = async (req: Request, res: Response) => {
    sendPage(res, await this.service.list(req.validated.query as ListDevEmailsQuery));
  };
}
