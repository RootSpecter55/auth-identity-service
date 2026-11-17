import { Router, type RequestHandler } from 'express';
import { validate } from '../../common/validate';
import type { SessionsController } from './sessions.controller';
import {
  listSessionsQuery,
  loginBody,
  loginMfaBody,
  refreshBody,
  sessionParams,
} from './sessions.schemas';

/** Mounted at /auth: getting, renewing and ending tokens. */
export function authRoutes(controller: SessionsController, authenticate: RequestHandler): Router {
  const router = Router();
  router.post('/login', validate({ body: loginBody }), controller.login);
  router.post('/login/mfa', validate({ body: loginMfaBody }), controller.loginMfa);
  router.post('/refresh', validate({ body: refreshBody }), controller.refresh);
  router.post('/logout', authenticate, controller.logout);
  return router;
}

/** Mounted at /sessions: a user's own active sessions. */
export function sessionsRoutes(
  controller: SessionsController,
  authenticate: RequestHandler,
): Router {
  const router = Router();
  router.use(authenticate);
  router.get('/', validate({ query: listSessionsQuery }), controller.list);
  router.delete('/:sessionId', validate({ params: sessionParams }), controller.revoke);
  return router;
}
