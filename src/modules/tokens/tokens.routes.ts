import { Router } from 'express';
import type { TokensController } from './tokens.controller';

/** Mounted at /.well-known. Public. */
export function tokensRoutes(controller: TokensController): Router {
  const router = Router();
  router.get('/jwks.json', controller.jwks);
  return router;
}
