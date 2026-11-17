import express, { type Express } from 'express';
import { pinoHttp } from 'pino-http';
import { errorHandler, notFoundHandler } from './common/error-handler';
import { logger } from './common/logger';
import { sendData } from './common/response';
import { buildContainer, type Container } from './container';
import { adminRoutes } from './modules/admin/admin.routes';
import { devEmailsRoutes } from './modules/dev-emails/dev-emails.routes';
import { emailVerificationRoutes } from './modules/email-verification/email-verification.routes';
import { mfaRoutes } from './modules/mfa/mfa.routes';
import { passwordResetRoutes } from './modules/password-reset/password-reset.routes';
import { rolesRoutes } from './modules/roles/roles.routes';
import { authRoutes, sessionsRoutes } from './modules/sessions/sessions.routes';
import { tokensRoutes } from './modules/tokens/tokens.routes';
import { usersRoutes } from './modules/users/users.routes';

export function createApp(container: Container = buildContainer()): Express {
  const { controllers: c, authenticate, config } = container;
  const app = express();
  app.disable('x-powered-by');
  // Behind a load balancer, req.ip (used for throttling) must come from X-Forwarded-For.
  app.set('trust proxy', config.TRUST_PROXY);
  app.use(
    pinoHttp({
      logger,
      // Never log credentials or tokens.
      redact: ['req.headers.authorization', 'req.headers.cookie'],
    }),
  );
  app.use(express.json({ limit: '16kb' }));

  app.get('/health', (_req, res) => sendData(res, { status: 'ok' }));

  app.use('/.well-known', tokensRoutes(c.tokens));
  app.use('/users', usersRoutes(c.users, authenticate));
  app.use('/auth', authRoutes(c.sessions, authenticate));
  app.use('/sessions', sessionsRoutes(c.sessions, authenticate));
  app.use('/email-verification', emailVerificationRoutes(c.verification, authenticate));
  app.use('/password-reset', passwordResetRoutes(c.passwordReset));
  app.use('/mfa', mfaRoutes(c.mfa, authenticate));
  app.use('/roles', rolesRoutes(c.roles, authenticate));
  app.use('/admin', adminRoutes(c.admin, authenticate));
  if (config.DEV_ENDPOINTS) app.use('/dev/emails', devEmailsRoutes(c.devEmails));

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
