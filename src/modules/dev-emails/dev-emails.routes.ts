import { Router } from 'express';
import { validate } from '../../common/validate';
import type { DevEmailsController } from './dev-emails.controller';
import { listDevEmailsQuery } from './dev-emails.schemas';

/** Mounted at /dev/emails, and only when DEV_ENDPOINTS=true (which config allows only with the fake provider). */
export function devEmailsRoutes(controller: DevEmailsController): Router {
  const router = Router();
  router.get('/', validate({ query: listDevEmailsQuery }), controller.list);
  return router;
}
