import { Router } from 'express';
import { validate } from '../../common/validate';
import type { PasswordResetController } from './password-reset.controller';
import { confirmResetBody, requestResetBody } from './password-reset.schemas';

/** Mounted at /password-reset. Public. */
export function passwordResetRoutes(controller: PasswordResetController): Router {
  const router = Router();
  router.post('/request', validate({ body: requestResetBody }), controller.request);
  router.post('/confirm', validate({ body: confirmResetBody }), controller.confirm);
  return router;
}
