import type { Request, Response } from 'express';
import { currentUser } from '../../common/auth-middleware';
import { sendData } from '../../common/response';
import type { ChangePasswordInput, RegisterInput, UpdateMeInput } from './users.schemas';
import type { UsersService } from './users.service';

export class UsersController {
  constructor(private readonly service: UsersService) {}

  register = async (req: Request, res: Response) => {
    sendData(res, await this.service.register(req.validated.body as RegisterInput), 202);
  };

  me = async (req: Request, res: Response) => {
    sendData(res, await this.service.me(currentUser(req).id));
  };

  updateMe = async (req: Request, res: Response) => {
    const input = req.validated.body as UpdateMeInput;
    sendData(res, await this.service.updateMe(currentUser(req).id, input));
  };

  changePassword = async (req: Request, res: Response) => {
    await this.service.changePassword(currentUser(req), req.validated.body as ChangePasswordInput);
    res.status(204).end();
  };
}
