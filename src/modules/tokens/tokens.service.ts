import { randomUUID } from 'node:crypto';
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import type { Db, DbContext } from '../../common/db';
import { isUniqueViolation } from '../../common/db';
import { UnauthorizedError } from '../../common/errors';
import { toPage, toSkipTake, type PaginationQuery } from '../../common/pagination';
import type { SigningKey } from '../../generated/prisma/client';
import type { KeyStore, PublicJwk } from '../../providers/key-store';
import type { SigningKeyRepository } from './tokens.repository';

/** Extra time a retired key stays published, to allow for clocks that disagree. */
const CLOCK_SKEW_SECONDS = 60;

export type AccessTokenClaims = {
  sub: string;
  sid: string;
  roles: string[];
  email_verified: boolean;
};

export type TokenOptions = { issuer: string; audience: string; accessTokenTtlSeconds: number };

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function toJwk(key: SigningKey) {
  return { ...(key.publicJwk as PublicJwk), kid: key.id, alg: 'ES256', use: 'sig' };
}

/**
 * Issues and verifies ES256 access tokens, and manages the signing keys behind them.
 *
 * The JWT is assembled here and only the signature comes from the KeyStore, so it works the
 * same whether the private key is local or in KMS. Verification uses the public keys from the
 * database, the same set /.well-known/jwks.json publishes.
 */
export class TokensService {
  /** Public keys by kid. Reloaded when a token names a kid we have not seen. */
  private publicKeys = new Map<string, JWK>();

  constructor(
    private readonly db: DbContext,
    private readonly keys: SigningKeyRepository,
    private readonly keyStore: KeyStore,
    private readonly options: TokenOptions,
  ) {}

  /** Creates a key row in the given state, with its private half in the KeyStore. */
  private async createKey(db: Db, status: 'NEXT' | 'ACTIVE'): Promise<SigningKey> {
    const { publicJwk, privateKeyRef } = await this.keyStore.createKey();
    return this.keys.create(db, {
      id: randomUUID(),
      publicJwk,
      privateKeyRef,
      keyStore: this.keyStore.name,
      status,
    });
  }

  /**
   * Makes sure an ACTIVE and a NEXT key exist (on a fresh database, the first call creates
   * them). If another instance creates one at the same moment, the partial unique indexes let
   * only one win, and this instance uses that one.
   */
  private async ensureKeys(): Promise<{ active: SigningKey; next: SigningKey }> {
    const db = this.db.client();
    const ensure = async (status: 'NEXT' | 'ACTIVE') => {
      const find = () => (status === 'ACTIVE' ? this.keys.findActive(db) : this.keys.findNext(db));
      const existing = await find();
      if (existing) return existing;
      try {
        return await this.createKey(db, status);
      } catch (err) {
        if (!isUniqueViolation(err)) throw err;
        return (await find())!;
      }
    };
    return { active: await ensure('ACTIVE'), next: await ensure('NEXT') };
  }

  async issueAccessToken(claims: AccessTokenClaims): Promise<{ token: string; expiresIn: number }> {
    const { active: key } = await this.ensureKeys();
    const now = Math.floor(Date.now() / 1000);
    const ttl = this.options.accessTokenTtlSeconds;
    const header = { alg: 'ES256', typ: 'JWT', kid: key.id };
    const payload = {
      ...claims,
      iss: this.options.issuer,
      aud: this.options.audience,
      iat: now,
      exp: now + ttl,
      jti: randomUUID(),
    };
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
    const signature = await this.keyStore.sign(key.privateKeyRef, Buffer.from(signingInput));
    return { token: `${signingInput}.${base64url(signature)}`, expiresIn: ttl };
  }

  /** Verifies signature, issuer, audience and expiry. Throws UnauthorizedError otherwise. */
  async verifyAccessToken(token: string): Promise<AccessTokenClaims & JWTPayload> {
    try {
      const { kid, alg } = decodeProtectedHeader(token);
      if (alg !== 'ES256' || !kid) throw new Error('Unexpected token header');
      let jwk = this.publicKeys.get(kid);
      if (!jwk) {
        await this.reloadPublicKeys();
        jwk = this.publicKeys.get(kid);
      }
      if (!jwk) throw new Error('Unknown key id');
      const { payload } = await jwtVerify(token, await importJWK(jwk, 'ES256'), {
        issuer: this.options.issuer,
        audience: this.options.audience,
        algorithms: ['ES256'],
      });
      return payload as AccessTokenClaims & JWTPayload;
    } catch {
      throw new UnauthorizedError('Invalid or expired token');
    }
  }

  private async reloadPublicKeys() {
    const published = await this.keys.findPublished(this.db.client(), new Date());
    this.publicKeys = new Map(published.map((key) => [key.id, toJwk(key)]));
  }

  /**
   * The JWKS document: every key a valid, unexpired token could have been signed with, plus
   * the NEXT key, published ahead of time so caches already hold it when it starts signing.
   */
  async jwks() {
    await this.ensureKeys();
    const published = await this.keys.findPublished(this.db.client(), new Date());
    return { keys: published.map(toJwk) };
  }

  /**
   * Rotation, in one transaction: ACTIVE -> RETIRED, NEXT -> ACTIVE, and a new NEXT.
   *
   * The key that starts signing has been in the JWKS since the previous rotation, so resource
   * servers have it cached already. (JWKS clients rate-limit refetches; jose waits 30 s by
   * default, so a key published at the moment it starts signing would be rejected for a while.)
   * The retired key stays published until every token it signed has expired: now + access-token
   * TTL + clock skew.
   */
  async rotate() {
    const { active, next } = await this.ensureKeys();
    const { publicJwk, privateKeyRef } = await this.keyStore.createKey();
    const now = new Date();
    const publishUntil = new Date(
      now.getTime() + (this.options.accessTokenTtlSeconds + CLOCK_SKEW_SECONDS) * 1000,
    );
    const upcoming = await this.db.transaction(async (tx) => {
      await this.keys.retire(tx, active.id, now, publishUntil);
      await this.keys.promote(tx, next.id);
      return this.keys.create(tx, {
        id: randomUUID(),
        publicJwk,
        privateKeyRef,
        keyStore: this.keyStore.name,
        status: 'NEXT',
      });
    });
    this.publicKeys.clear();
    return {
      kid: next.id,
      nextKid: upcoming.id,
      previousKid: active.id,
      previousPublishedUntil: publishUntil,
    };
  }

  async listKeys(query: PaginationQuery) {
    const { items, total } = await this.keys.list(this.db.client(), {
      ...toSkipTake(query),
      orderBy: { createdAt: 'desc' },
    });
    // Never return privateKeyRef, even encrypted.
    const views = items.map(({ privateKeyRef: _omit, ...key }) => key);
    return toPage(views, total, query);
  }
}
