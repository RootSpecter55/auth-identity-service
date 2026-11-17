import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { createResourceServer } from '../../examples/resource-server/server';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { buildContainer } from '../../src/container';
import { adminSession, bearer, closeShared, login, register, resetState } from './helpers';

const container = buildContainer();
const app = createApp(container);
let authServer: Server;
let jwksUrl: string;
let resourceServer: Server;
let resourceUrl: string;

function listen(server: Server): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
  );
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

beforeAll(async () => {
  // The resource server fetches the JWKS over real HTTP, so the auth app gets a real port.
  authServer = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => authServer.once('listening', resolve));
  jwksUrl = `http://127.0.0.1:${(authServer.address() as AddressInfo).port}/.well-known/jwks.json`;
});
// A fresh resource server per test: its JWKS cache must not outlive the keys a reset deletes.
beforeEach(async () => {
  await resetState();
  resourceServer = createResourceServer({
    jwksUrl,
    issuer: 'http://localhost:3000',
    audience: 'api',
  });
  resourceUrl = `http://127.0.0.1:${await listen(resourceServer)}`;
});
afterEach(async () => {
  resourceServer.closeAllConnections();
  await close(resourceServer);
});
afterAll(async () => {
  authServer.closeAllConnections();
  await close(authServer);
  await closeShared();
});

function callResource(accessToken: string) {
  return request(resourceUrl)
    .get('/notes')
    .set({ Authorization: `Bearer ${accessToken}` });
}

function kidOf(jwt: string): string {
  return JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString()).kid;
}

describe('JWKS and key rotation', () => {
  it('publishes ES256 public keys only, and stores private keys encrypted', async () => {
    await register(app, 'ada@example.com');
    const tokens = await login(app, 'ada@example.com');

    // The signing key, and the next one, published before it is ever used.
    const jwks = await request(app).get('/.well-known/jwks.json').expect(200);
    expect(jwks.body.keys).toHaveLength(2);
    expect(jwks.body.keys.map((k: { kid: string }) => k.kid)).toContain(kidOf(tokens.accessToken));
    for (const key of jwks.body.keys) {
      expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
      expect(key).not.toHaveProperty('d');
    }

    for (const key of await getPrisma().signingKey.findMany()) {
      expect(key.privateKeyRef).toMatch(/^v1\./);
      expect(key.privateKeyRef).not.toContain('PRIVATE KEY');
    }
  });

  it('keeps verifying old tokens after a rotation, until the old key leaves the JWKS', async () => {
    const admin = await adminSession(app);
    const before = admin.tokens.accessToken;
    expect((await callResource(before)).status).toBe(200);

    const rotated = await request(app)
      .post('/admin/keys/rotate')
      .set(bearer(admin.tokens))
      .expect(201);
    expect(rotated.body.data.previousKid).toBe(kidOf(before));

    // New logins are signed with the new key; the old token still verifies everywhere.
    const after = (await login(app, 'admin@example.com')).accessToken;
    expect(kidOf(after)).toBe(rotated.body.data.kid);
    expect((await callResource(before)).status).toBe(200);
    expect((await callResource(after)).status).toBe(200);
    await request(app)
      .get('/users/me')
      .set(bearer({ accessToken: before }))
      .expect(200);

    const jwks = await request(app).get('/.well-known/jwks.json');
    expect(jwks.body.keys.map((k: { kid: string }) => k.kid).sort()).toEqual(
      [kidOf(before), kidOf(after), rotated.body.data.nextKid].sort(),
    );

    // Its publish window has passed (every token it signed has expired by then).
    await getPrisma().signingKey.updateMany({
      where: { status: 'RETIRED' },
      data: { publishUntil: new Date(Date.now() - 1000) },
    });
    const later = await request(app).get('/.well-known/jwks.json');
    expect(later.body.keys.map((k: { kid: string }) => k.kid).sort()).toEqual(
      [kidOf(after), rotated.body.data.nextKid].sort(),
    );
  });

  it('sets the publish window to the access-token lifetime plus clock skew', async () => {
    const admin = await adminSession(app);
    const started = Date.now();
    const res = await request(app).post('/admin/keys/rotate').set(bearer(admin.tokens)).expect(201);
    const until = new Date(res.body.data.previousPublishedUntil).getTime();
    expect(until - started).toBeGreaterThanOrEqual((900 + 60) * 1000 - 1000);
    expect(until - started).toBeLessThanOrEqual((900 + 60) * 1000 + 5000);

    const keys = await request(app).get('/admin/keys').set(bearer(admin.tokens)).expect(200);
    expect(keys.body.data.map((k: { status: string }) => k.status).sort()).toEqual([
      'ACTIVE',
      'NEXT',
      'RETIRED',
    ]);
    expect(keys.body.data[0]).not.toHaveProperty('privateKeyRef');
  });
});

describe('example resource server', () => {
  it('rejects a missing, tampered, expired or wrong-audience token', async () => {
    await register(app, 'ada@example.com');
    const { accessToken } = await login(app, 'ada@example.com');
    expect((await request(resourceUrl).get('/notes')).status).toBe(401);

    const [header, payload, signature] = accessToken.split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString());
    const forged = Buffer.from(JSON.stringify({ ...claims, roles: ['admin'] })).toString(
      'base64url',
    );
    expect((await callResource(`${header}.${forged}.${signature}`)).status).toBe(401);

    // Signed with the real key, but for another audience.
    const otherAudience = buildContainer({ config: { JWT_AUDIENCE: 'billing' } });
    const wrong = await otherAudience.services.tokens.issueAccessToken({
      sub: claims.sub,
      sid: claims.sid,
      roles: [],
      email_verified: true,
    });
    expect((await callResource(wrong.token)).status).toBe(401);

    // Signed with the real key, but already expired.
    const realNow = Date.now;
    jest.spyOn(Date, 'now').mockReturnValue(realNow() - 2 * 60 * 60 * 1000);
    const expired = await container.services.tokens.issueAccessToken({
      sub: claims.sub,
      sid: claims.sid,
      roles: [],
      email_verified: true,
    });
    jest.restoreAllMocks();
    expect((await callResource(expired.token)).status).toBe(401);

    const ok = await callResource(accessToken);
    expect(ok.body.data).toEqual({ notesFor: claims.sub, roles: ['user'], adminView: false });
  });
});
