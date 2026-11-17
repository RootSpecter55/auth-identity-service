import { Router, type RequestHandler } from 'express';
import { validate } from '../../common/validate';
import type { MfaController } from './mfa.controller';
import { totpCodeBody } from './mfa.schemas';

/** Mounted at /mfa. Every route needs a logged-in user. */
export function mfaRoutes(controller: MfaController, authenticate: RequestHandler): Router {
  const router = Router();
  router.use(authenticate);
  const withCode = validate({ body: totpCodeBody });
  router.post('/totp/enroll', controller.enroll);
  router.post('/totp/activate', withCode, controller.activate);
  router.post('/totp/disable', withCode, controller.disable);
  router.post('/recovery-codes', withCode, controller.regenerateRecoveryCodes);
  return router;
}
