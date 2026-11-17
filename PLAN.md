# PLAN — auth-identity-service

A standalone identity service that other backends trust. It covers:

- Users register, verify their email, log in (optionally with TOTP), refresh and log out.
- Short-lived ES256 access tokens. Any backend can verify them with only the public keys at `/.well-known/jwks.json`.
- Opaque refresh tokens, rotated on every use, with reuse detection.
- Login throttling, password reset and roles.

**Stack:** Node 24, TypeScript 5.9 (strict), Express 5, Prisma 7, Zod 4, PostgreSQL 16, Redis 7 (login throttling only), `@node-rs/argon2` (argon2id), `jose` 5 (JWT verification and remote JWKS), Jest 30 with Supertest, ESLint and Prettier.

## Modules

| Module             | Responsibility                                                                                                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| users              | Register (always 202, so it never reveals whether an email exists), `me`, update profile, change password (revokes the other sessions).                                                       |
| sessions           | Login (Redis throttling per account and per IP, same answer for unknown email and wrong password), MFA step, refresh with rotation and reuse detection, logout, list and revoke own sessions. |
| tokens             | Signing keys (rows in Postgres; private halves behind `KeyStore`), JWT signing (ES256 with `kid`), verification, JWKS endpoint, key rotation with a publish-until date.                       |
| mfa                | TOTP enrolment, activation and disable, hashed one-time recovery codes, and the login challenge check (with replay protection on time steps).                                                 |
| email-verification | Token emailed at registration; confirm, resend.                                                                                                                                               |
| password-reset     | Request (always 202), confirm (sets the password, revokes every session).                                                                                                                     |
| roles              | List and create roles.                                                                                                                                                                        |
| admin              | List users, grant and revoke roles, disable and enable users (disabling revokes sessions), list and rotate signing keys. Requires the `admin` role.                                           |

**Shared (`src/common/`):** config, logger, errors and the error handler, `validate`, pagination, auth middleware (JWT plus session check, role guard), base repository, Prisma, Redis, response helpers, `crypto.ts` (AES-256-GCM encryption with `KEY_ENCRYPTION_KEY`, SHA-256 token hashing, random tokens).

**Providers:** `KeyStore` (local: P-256 private keys encrypted with AES-256-GCM, stored in Postgres; KMS: asymmetric `ECC_NIST_P256` keys, signing in KMS, untested) and `EmailProvider` (fake: stores mail in a `dev_emails` table, readable through a dev-only endpoint; SES v2, untested). A factory picks each from config.

**Example resource server (`examples/resource-server/`):** under 100 lines. It verifies access tokens using only the JWKS URL (`jose` `createRemoteJWKSet`), and has its own test.

## Data model

```
User          id, email (unique, lower-case), name, passwordHash, emailVerifiedAt?, disabledAt?, createdAt, updatedAt
Role          id, name (unique), description          UserRole   userId + roleId (PK)
Session       id, userId, userAgent?, ipAddress?, createdAt, lastUsedAt, expiresAt, revokedAt?, revokedReason?
RefreshToken  id, sessionId, tokenHash (unique), status (ACTIVE|ROTATED|REVOKED), expiresAt, createdAt, usedAt?
SigningKey    id (= kid), publicJwk, privateKeyRef, keyStore (local|kms), status (ACTIVE|RETIRED), createdAt, retiredAt?, publishUntil?
TotpFactor    id, userId (unique), secretEncrypted, status (PENDING|ACTIVE), lastUsedStep?, createdAt, activatedAt?
RecoveryCode  id, userId, codeHash, usedAt?
MfaChallenge  id, userId, tokenHash (unique), attempts, expiresAt, usedAt?
EmailToken    id, userId, purpose (VERIFY_EMAIL|RESET_PASSWORD), tokenHash (unique), expiresAt, usedAt?
DevEmail      id, to, subject, text, createdAt                (fake email provider only)
```

A session is a refresh-token family: every refresh token in it descends from one login.

## Mechanisms and the tests that prove them

- **Refresh rotation and reuse detection.** A refresh token is 256 random bits, stored as SHA-256. Using one marks it ROTATED (compare-and-set on `status = 'ACTIVE'`) and issues a successor in the same session. Presenting a ROTATED token again means it was copied, so the whole family is revoked: the session and every refresh token in it. _Test:_ refresh A → B; reuse A → 401 and B no longer works either; the session shows as revoked.
- **ES256 with key rotation.** Tokens carry `kid`. Rotation makes a new ACTIVE key and RETIRES the old one with `publishUntil = now + access-token TTL + 60 s skew`. JWKS lists ACTIVE keys plus RETIRED keys still inside `publishUntil`. _Test:_ a token signed before rotation still verifies through JWKS; new tokens use the new `kid`; once `publishUntil` passes, the old key leaves JWKS.
- **The service's own endpoints** also check that the token's session (`sid`) isn't revoked, so logout takes effect immediately there. Other resource servers rely on the short TTL (documented).
- **argon2id** (OWASP parameters: 19 MiB, t=2, p=1). Unknown emails are verified against a dummy hash, so timing doesn't reveal whether an account exists.
- **Login throttling** (Redis fixed windows, `INCR` plus `EXPIRE`): failures per email hash and per IP. Over the limit gives 429 with `Retry-After`, even for an email that doesn't exist. A successful login clears the account counter. _Tests:_ lockout after N failures; identical responses for an unknown email and a wrong password.
- **TOTP (RFC 6238, written with `node:crypto`)** with ±1 step tolerance. A step at or before `lastUsedStep` is rejected (no replay). Ten recovery codes are shown once, stored hashed and single-use. Login with MFA returns a short-lived `mfaToken`, limited to 5 code attempts. _Tests:_ RFC 6238 vectors (unit), enrol → activate → login, code replay rejected, recovery code works once.
- **Email flows** go through the fake provider: verification and reset tokens are hashed, expire and are single-use; reset revokes every session.
- **Resource server example:** verifies tokens from the service using only its JWKS URL. Rejects tampered, expired and wrong-audience tokens. Still accepts pre-rotation tokens after a rotation.

## Endpoints

Envelope: `{ data, meta? }` / `{ error: { code, message, details? } }`. Lists are paginated.

```
GET  /health                       GET  /.well-known/jwks.json
POST /users                        202 always          GET/PATCH /users/me     POST /users/me/password
POST /auth/login                   tokens, or {mfaRequired, mfaToken}
POST /auth/login/mfa               {mfaToken, code | recoveryCode}
POST /auth/refresh                 {refreshToken}      POST /auth/logout
GET  /sessions                     DELETE /sessions/:sessionId
POST /email-verification/confirm   POST /email-verification/resend
POST /password-reset/request       202 always          POST /password-reset/confirm
POST /mfa/totp/enroll              POST /mfa/totp/activate        POST /mfa/totp/disable
POST /mfa/recovery-codes           regenerate (needs a current code)
GET  /roles                        POST /roles [admin]
GET  /admin/users                  POST /admin/users/:id/roles    DELETE /admin/users/:id/roles/:role
POST /admin/users/:id/disable      POST /admin/users/:id/enable
GET  /admin/keys                   POST /admin/keys/rotate
GET  /dev/emails                   only when DEV_ENDPOINTS=true (refused unless EMAIL_PROVIDER=fake)
```

## Build order

1. Scaffold. 2. Common layer, crypto helpers, schema and seed (roles). 3. tokens with KeyStore and JWKS. 4. users and email. 5. sessions: login, throttling, refresh rotation. 6. mfa. 7. password reset, roles, admin. 8. Example resource server. 9. Tests. 10. Deployment files. 11. README.
