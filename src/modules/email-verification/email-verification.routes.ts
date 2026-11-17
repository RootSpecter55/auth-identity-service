import { Router, type RequestHandler } from 'express';
import { validate } from '../../common/validate';
import type { EmailVerificationController } from './email-verification.controller';
import { confirmEmailBody } from './email-verification.schemas';

/** Mounted at /email-verification. */
export function emailVerificationRoutes(
  controller: EmailVerificationController,
  authenticate: RequestHandler,
): Router {
  const router = Router();
  router.post('/confirm', validate({ body: confirmEmailBody }), controller.confirm);
  router.post('/resend', authenticate, controller.resend);
  return router;
}
