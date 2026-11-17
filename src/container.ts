import { createAuthMiddleware } from './common/auth-middleware';
import { getConfig, type Config } from './common/config';
import { dbContext } from './common/db';
import { getRedis } from './common/redis';
import { AdminController } from './modules/admin/admin.controller';
import { AdminService } from './modules/admin/admin.service';
import { DevEmailsController } from './modules/dev-emails/dev-emails.controller';
import { DevEmailRepository } from './modules/dev-emails/dev-emails.repository';
import { DevEmailsService } from './modules/dev-emails/dev-emails.service';
import { EmailTokenRepository } from './modules/email-verification/email-tokens.repository';
import { EmailVerificationController } from './modules/email-verification/email-verification.controller';
import { EmailVerificationService } from './modules/email-verification/email-verification.service';
import { MfaController } from './modules/mfa/mfa.controller';
import {
  MfaChallengeRepository,
  RecoveryCodeRepository,
  TotpRepository,
} from './modules/mfa/mfa.repository';
import { MfaService } from './modules/mfa/mfa.service';
import { PasswordResetController } from './modules/password-reset/password-reset.controller';
import { PasswordResetService } from './modules/password-reset/password-reset.service';
import { RolesController } from './modules/roles/roles.controller';
import { RoleRepository } from './modules/roles/roles.repository';
import { RolesService } from './modules/roles/roles.service';
import { LoginThrottle } from './modules/sessions/login-throttle';
import { SessionsController } from './modules/sessions/sessions.controller';
import { RefreshTokenRepository, SessionRepository } from './modules/sessions/sessions.repository';
import { SessionsService } from './modules/sessions/sessions.service';
import { TokensController } from './modules/tokens/tokens.controller';
import { SigningKeyRepository } from './modules/tokens/tokens.repository';
import { TokensService } from './modules/tokens/tokens.service';
import { UsersController } from './modules/users/users.controller';
import { UserRepository } from './modules/users/users.repository';
import { UsersService } from './modules/users/users.service';
import { createEmailProvider, type EmailProvider } from './providers/email';
import { createKeyStore, type KeyStore } from './providers/key-store';

/** Tests replace config values or providers here instead of patching modules. */
export type ContainerOverrides = {
  config?: Partial<Config>;
  keyStore?: KeyStore;
  email?: EmailProvider;
};

/** Composition root: builds every provider, repository, service and controller in one place. */
export function buildContainer(overrides: ContainerOverrides = {}) {
  const config: Config = { ...getConfig(), ...overrides.config };
  const encryptionKey = Buffer.from(config.KEY_ENCRYPTION_KEY, 'base64');
  const keyStore = overrides.keyStore ?? createKeyStore(config);
  const email = overrides.email ?? createEmailProvider(config);

  const repos = {
    users: new UserRepository(),
    roles: new RoleRepository(),
    sessions: new SessionRepository(),
    refreshTokens: new RefreshTokenRepository(),
    signingKeys: new SigningKeyRepository(),
    totp: new TotpRepository(),
    recoveryCodes: new RecoveryCodeRepository(),
    challenges: new MfaChallengeRepository(),
    emailTokens: new EmailTokenRepository(),
    devEmails: new DevEmailRepository(),
  };

  const tokens = new TokensService(dbContext, repos.signingKeys, keyStore, {
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
    accessTokenTtlSeconds: config.ACCESS_TOKEN_TTL_SECONDS,
  });
  const verification = new EmailVerificationService(
    dbContext,
    repos.users,
    repos.emailTokens,
    email,
    config.APP_URL,
  );
  const mfa = new MfaService(
    dbContext,
    repos.users,
    repos.totp,
    repos.recoveryCodes,
    repos.challenges,
    encryptionKey,
    new URL(config.JWT_ISSUER).host,
  );
  const sessions = new SessionsService(
    dbContext,
    repos.users,
    repos.sessions,
    repos.refreshTokens,
    tokens,
    mfa,
    new LoginThrottle(getRedis(), {
      perAccount: config.LOGIN_MAX_FAILURES_PER_ACCOUNT,
      perIp: config.LOGIN_MAX_FAILURES_PER_IP,
      windowSeconds: config.LOGIN_THROTTLE_WINDOW_SECONDS,
    }),
    config.REFRESH_TOKEN_TTL_DAYS,
  );
  const services = {
    tokens,
    sessions,
    mfa,
    verification,
    users: new UsersService(
      dbContext,
      repos.users,
      repos.roles,
      repos.sessions,
      verification,
      email,
    ),
    passwordReset: new PasswordResetService(
      dbContext,
      repos.users,
      repos.emailTokens,
      repos.sessions,
      email,
      config.APP_URL,
    ),
    roles: new RolesService(dbContext, repos.roles),
    admin: new AdminService(dbContext, repos.users, repos.roles, repos.sessions, tokens),
    devEmails: new DevEmailsService(dbContext, repos.devEmails),
  };

  return {
    config,
    repos,
    services,
    authenticate: createAuthMiddleware(sessions.resolveUser),
    controllers: {
      tokens: new TokensController(services.tokens),
      users: new UsersController(services.users),
      sessions: new SessionsController(services.sessions),
      verification: new EmailVerificationController(services.verification),
      passwordReset: new PasswordResetController(services.passwordReset),
      mfa: new MfaController(services.mfa),
      roles: new RolesController(services.roles),
      admin: new AdminController(services.admin),
      devEmails: new DevEmailsController(services.devEmails),
    },
  };
}

export type Container = ReturnType<typeof buildContainer>;
