import type { Request, Response } from 'express';
import { currentUser } from '../../common/auth-middleware';
import type { ConfirmEmailInput } from './email-verification.schemas';
import type { EmailVerificationService } from './email-verification.service';

export class EmailVerificationController {
  constructor(private readonly service: EmailVerificationService) {}

  confirm = async (req: Request, res: Response) => {
    await this.service.confirm((req.validated.body as ConfirmEmailInput).token);
    res.status(204).end();
  };

  resend = async (req: Request, res: Response) => {
    await this.service.resend(currentUser(req).id);
    res.status(202).end();
  };
}
