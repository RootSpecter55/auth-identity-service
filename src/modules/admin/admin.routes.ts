import { Router, type RequestHandler } from 'express';
import { requireRole } from '../../common/auth-middleware';
import { validate } from '../../common/validate';
import type { AdminController } from './admin.controller';
import {
  grantRoleBody,
  listKeysQuery,
  listUsersQuery,
  userParams,
  userRoleParams,
} from './admin.schemas';

/** Mounted at /admin. Every route needs the admin role. */
export function adminRoutes(controller: AdminController, authenticate: RequestHandler): Router {
  const router = Router();
  router.use(authenticate, requireRole('admin'));
  router.get('/users', validate({ query: listUsersQuery }), controller.listUsers);
  router.post(
    '/users/:userId/roles',
    validate({ params: userParams, body: grantRoleBody }),
    controller.grantRole,
  );
  router.delete(
    '/users/:userId/roles/:role',
    validate({ params: userRoleParams }),
    controller.revokeRole,
  );
  router.post('/users/:userId/disable', validate({ params: userParams }), controller.disable);
  router.post('/users/:userId/enable', validate({ params: userParams }), controller.enable);
  router.get('/keys', validate({ query: listKeysQuery }), controller.listKeys);
  router.post('/keys/rotate', controller.rotateKey);
  return router;
}
