import type { Request, Response } from 'express';
import { sendData } from '../../common/response';
import type { ConfirmResetInput, RequestResetInput } from './password-reset.schemas';
import type { PasswordResetService } from './password-reset.service';

export class PasswordResetController {
  constructor(private readonly service: PasswordResetService) {}

  request = async (req: Request, res: Response) => {
    sendData(res, await this.service.request(req.validated.body as RequestResetInput), 202);
  };

  confirm = async (req: Request, res: Response) => {
    await this.service.confirm(req.validated.body as ConfirmResetInput);
    res.status(204).end();
  };
}
