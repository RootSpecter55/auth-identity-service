import type { Request, RequestHandler } from 'express';
import { ForbiddenError, UnauthorizedError } from './errors';

export type AuthUser = { id: string; sessionId: string; roles: string[] };

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

/** Turns a bearer token into a user, or throws. Supplied by the sessions module. */
export type ResolveUser = (accessToken: string) => Promise<AuthUser>;

export function createAuthMiddleware(resolveUser: ResolveUser): RequestHandler {
  return async (req, _res, next) => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return next(new UnauthorizedError());
    try {
      req.user = await resolveUser(header.slice('Bearer '.length));
      next();
    } catch {
      next(new UnauthorizedError('Invalid or expired token'));
    }
  };
}

/** Allows the request only if the authenticated user has `role`. Run after the auth middleware. */
export function requireRole(role: string): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) return next(new UnauthorizedError());
    if (!req.user.roles.includes(role)) return next(new ForbiddenError());
    next();
  };
}

/** The authenticated user. Only call after the auth middleware has run. */
export function currentUser(req: Request): AuthUser {
  if (!req.user) throw new UnauthorizedError();
  return req.user;
}

/** Client details recorded on a session. */
export function clientInfo(req: Request) {
  return { ipAddress: req.ip ?? null, userAgent: req.get('user-agent')?.slice(0, 500) ?? null };
}
