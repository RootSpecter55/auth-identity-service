import type { Request, Response } from 'express';
import { clientInfo, currentUser } from '../../common/auth-middleware';
import { sendData, sendPage } from '../../common/response';
import type {
  ListSessionsQuery,
  LoginInput,
  LoginMfaInput,
  RefreshInput,
  SessionParams,
} from './sessions.schemas';
import type { SessionsService } from './sessions.service';

export class SessionsController {
  constructor(private readonly service: SessionsService) {}

  login = async (req: Request, res: Response) => {
    sendData(res, await this.service.login(req.validated.body as LoginInput, clientInfo(req)));
  };

  loginMfa = async (req: Request, res: Response) => {
    sendData(
      res,
      await this.service.loginMfa(req.validated.body as LoginMfaInput, clientInfo(req)),
    );
  };

  refresh = async (req: Request, res: Response) => {
    sendData(res, await this.service.refresh((req.validated.body as RefreshInput).refreshToken));
  };

  logout = async (req: Request, res: Response) => {
    await this.service.logout(currentUser(req));
    res.status(204).end();
  };

  list = async (req: Request, res: Response) => {
    const query = req.validated.query as ListSessionsQuery;
    sendPage(res, await this.service.list(currentUser(req), query));
  };

  revoke = async (req: Request, res: Response) => {
    const { sessionId } = req.validated.params as SessionParams;
    await this.service.revoke(currentUser(req), sessionId);
    res.status(204).end();
  };
}
