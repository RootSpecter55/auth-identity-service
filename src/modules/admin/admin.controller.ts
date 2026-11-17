import type { Request, Response } from 'express';
import { currentUser } from '../../common/auth-middleware';
import { sendData, sendPage } from '../../common/response';
import type {
  GrantRoleInput,
  ListKeysQuery,
  ListUsersQuery,
  UserParams,
  UserRoleParams,
} from './admin.schemas';
import type { AdminService } from './admin.service';

export class AdminController {
  constructor(private readonly service: AdminService) {}

  listUsers = async (req: Request, res: Response) => {
    sendPage(res, await this.service.listUsers(req.validated.query as ListUsersQuery));
  };

  grantRole = async (req: Request, res: Response) => {
    const { userId } = req.validated.params as UserParams;
    const { role } = req.validated.body as GrantRoleInput;
    sendData(res, await this.service.grantRole(userId, role));
  };

  revokeRole = async (req: Request, res: Response) => {
    const { userId, role } = req.validated.params as UserRoleParams;
    sendData(res, await this.service.revokeRole(currentUser(req), userId, role));
  };

  disable = async (req: Request, res: Response) => {
    const { userId } = req.validated.params as UserParams;
    await this.service.disable(currentUser(req), userId);
    res.status(204).end();
  };

  enable = async (req: Request, res: Response) => {
    const { userId } = req.validated.params as UserParams;
    await this.service.enable(userId);
    res.status(204).end();
  };

  listKeys = async (req: Request, res: Response) => {
    sendPage(res, await this.service.listKeys(req.validated.query as ListKeysQuery));
  };

  rotateKey = async (_req: Request, res: Response) => {
    sendData(res, await this.service.rotateKey(), 201);
  };
}
