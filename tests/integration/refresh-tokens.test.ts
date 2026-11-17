import request from 'supertest';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { bearer, closeShared, login, register, resetState } from './helpers';

const app = createApp();
const email = 'ada@example.com';

beforeEach(async () => {
  await resetState();
  await register(app, email);
});
afterAll(closeShared);

function refresh(refreshToken: string) {
  return request(app).post('/auth/refresh').send({ refreshToken });
}

describe('refresh token rotation', () => {
  it('issues a new pair on every refresh and stores only hashes', async () => {
    const first = await login(app, email);
    const res = await refresh(first.refreshToken).expect(200);
    expect(res.body.data.refreshToken).not.toBe(first.refreshToken);
    expect(res.body.data.sessionId).toBe(first.sessionId);
    await request(app).get('/users/me').set(bearer(res.body.data)).expect(200);

    const rows = await getPrisma().refreshToken.findMany({ orderBy: { createdAt: 'asc' } });
    expect(rows.map((r) => r.status)).toEqual(['ROTATED', 'ACTIVE']);
    expect(rows.every((r) => /^[0-9a-f]{64}$/.test(r.tokenHash))).toBe(true);
    expect(rows.map((r) => r.tokenHash)).not.toContain(first.refreshToken);
  });

  it('revokes the whole family when a rotated refresh token is used again', async () => {
    const stolen = await login(app, email);
    const legit = (await refresh(stolen.refreshToken).expect(200)).body.data;

    // The copy kept by an attacker (or a buggy client) comes back.
    const reuse = await refresh(stolen.refreshToken);
    expect(reuse.status).toBe(401);

    // Everything descended from that login is now dead, including the newest token.
    await refresh(legit.refreshToken).expect(401);
    await request(app).get('/users/me').set(bearer(legit)).expect(401);
    const session = await getPrisma().session.findUniqueOrThrow({
      where: { id: stolen.sessionId },
    });
    expect(session.revokedReason).toBe('REFRESH_TOKEN_REUSE');
    const statuses = await getPrisma().refreshToken.findMany({ where: { sessionId: session.id } });
    expect(statuses.every((r) => r.status === 'REVOKED')).toBe(true);
  });

  it('keeps other sessions alive when one family is revoked', async () => {
    const phone = await login(app, email);
    const laptop = await login(app, email);
    await refresh(phone.refreshToken).expect(200);
    await refresh(phone.refreshToken).expect(401);

    await refresh(laptop.refreshToken).expect(200);
  });

  it('treats two simultaneous uses of one token as reuse: one wins, then the family is revoked', async () => {
    const pair = await login(app, email);
    const results = await Promise.all([refresh(pair.refreshToken), refresh(pair.refreshToken)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
    const session = await getPrisma().session.findUniqueOrThrow({ where: { id: pair.sessionId } });
    expect(session.revokedAt).not.toBeNull();
  });

  it('rejects unknown and expired refresh tokens', async () => {
    await refresh('x'.repeat(43)).expect(401);
    const pair = await login(app, email);
    await getPrisma().refreshToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    await refresh(pair.refreshToken).expect(401);
  });
});

describe('sessions', () => {
  it('logout ends the session immediately for this service', async () => {
    const pair = await login(app, email);
    await request(app).post('/auth/logout').set(bearer(pair)).expect(204);
    await request(app).get('/users/me').set(bearer(pair)).expect(401);
    await refresh(pair.refreshToken).expect(401);
  });

  it('lists my sessions, marks the current one, and revokes another', async () => {
    const other = await login(app, email);
    const current = await login(app, email);

    const list = await request(app).get('/sessions').set(bearer(current)).expect(200);
    expect(list.body.meta.total).toBe(2);
    const mine = list.body.data.find((s: { id: string }) => s.id === current.sessionId);
    expect(mine.current).toBe(true);

    await request(app).delete(`/sessions/${other.sessionId}`).set(bearer(current)).expect(204);
    await refresh(other.refreshToken).expect(401);
    expect((await request(app).get('/sessions').set(bearer(current))).body.meta.total).toBe(1);
  });

  it('cannot revoke somebody else’s session', async () => {
    await register(app, 'bob@example.com');
    const bob = await login(app, 'bob@example.com');
    const ada = await login(app, email);
    await request(app).delete(`/sessions/${bob.sessionId}`).set(bearer(ada)).expect(404);
  });

  it('changing the password signs out the other sessions but keeps this one', async () => {
    const other = await login(app, email);
    const current = await login(app, email);
    await request(app)
      .post('/users/me/password')
      .set(bearer(current))
      .send({
        currentPassword: 'correct horse battery staple',
        newPassword: 'an even longer new password',
      })
      .expect(204);
    await request(app).get('/users/me').set(bearer(current)).expect(200);
    await request(app).get('/users/me').set(bearer(other)).expect(401);
    await login(app, email, 'an even longer new password');
  });
});
