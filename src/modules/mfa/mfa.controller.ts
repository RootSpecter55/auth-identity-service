import type { Request, Response } from 'express';
import { currentUser } from '../../common/auth-middleware';
import { sendData } from '../../common/response';
import type { TotpCodeInput } from './mfa.schemas';
import type { MfaService } from './mfa.service';

export class MfaController {
  constructor(private readonly service: MfaService) {}

  enroll = async (req: Request, res: Response) => {
    sendData(res, await this.service.enroll(currentUser(req).id), 201);
  };

  activate = async (req: Request, res: Response) => {
    const { code } = req.validated.body as TotpCodeInput;
    sendData(res, await this.service.activate(currentUser(req).id, code));
  };

  disable = async (req: Request, res: Response) => {
    const { code } = req.validated.body as TotpCodeInput;
    await this.service.disable(currentUser(req).id, code);
    res.status(204).end();
  };

  regenerateRecoveryCodes = async (req: Request, res: Response) => {
    const { code } = req.validated.body as TotpCodeInput;
    sendData(res, await this.service.regenerateRecoveryCodes(currentUser(req).id, code));
  };
}
