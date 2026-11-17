import { Router, type RequestHandler } from 'express';
import { validate } from '../../common/validate';
import type { UsersController } from './users.controller';
import { changePasswordBody, registerBody, updateMeBody } from './users.schemas';

/** Mounted at /users. */
export function usersRoutes(controller: UsersController, authenticate: RequestHandler): Router {
  const router = Router();
  router.post('/', validate({ body: registerBody }), controller.register);
  router.get('/me', authenticate, controller.me);
  router.patch('/me', authenticate, validate({ body: updateMeBody }), controller.updateMe);
  router.post(
    '/me/password',
    authenticate,
    validate({ body: changePasswordBody }),
    controller.changePassword,
  );
  return router;
}
