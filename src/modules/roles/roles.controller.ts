import type { Request, Response } from 'express';
import { sendData, sendPage } from '../../common/response';
import type { CreateRoleInput, ListRolesQuery } from './roles.schemas';
import type { RolesService } from './roles.service';

export class RolesController {
  constructor(private readonly service: RolesService) {}

  list = async (req: Request, res: Response) => {
    sendPage(res, await this.service.list(req.validated.query as ListRolesQuery));
  };

  create = async (req: Request, res: Response) => {
    sendData(res, await this.service.create(req.validated.body as CreateRoleInput), 201);
  };
}
