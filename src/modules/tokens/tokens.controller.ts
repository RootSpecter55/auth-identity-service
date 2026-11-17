import type { Request, Response } from 'express';
import type { TokensService } from './tokens.service';

export class TokensController {
  constructor(private readonly service: TokensService) {}

  /** Served as a bare JWKS document (not in the envelope): that is the format JWT libraries read. */
  jwks = async (_req: Request, res: Response) => {
    res.set('Cache-Control', 'public, max-age=300');
    res.json(await this.service.jwks());
  };
}
