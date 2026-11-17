import { Router, type RequestHandler } from 'express';
import { requireRole } from '../../common/auth-middleware';
import { validate } from '../../common/validate';
import type { RolesController } from './roles.controller';
import { createRoleBody, listRolesQuery } from './roles.schemas';

/** Mounted at /roles. Listing needs a login; creating needs the admin role. */
export function rolesRoutes(controller: RolesController, authenticate: RequestHandler): Router {
  const router = Router();
  router.use(authenticate);
  router.get('/', validate({ query: listRolesQuery }), controller.list);
  router.post('/', requireRole('admin'), validate({ body: createRoleBody }), controller.create);
  return router;
}
