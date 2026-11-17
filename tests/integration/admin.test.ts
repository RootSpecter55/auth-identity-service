import request from 'supertest';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { buildContainer } from '../../src/container';
import { adminSession, bearer, closeShared, login, register, resetState } from './helpers';

const app = createApp();

beforeEach(resetState);
afterAll(closeShared);

describe('admin', () => {
  it('is forbidden without the admin role', async () => {
    await register(app, 'ada@example.com');
    const tokens = await login(app, 'ada@example.com');
    await request(app).get('/admin/users').set(bearer(tokens)).expect(403);
    await request(app).get('/admin/users').expect(401);
  });

  it('grants a role, which appears in the token at the next refresh', async () => {
    const admin = await adminSession(app);
    const ada = await register(app, 'ada@example.com');
    const adaTokens = await login(app, 'ada@example.com');

    await request(app)
      .post('/roles')
      .set(bearer(admin.tokens))
      .send({ name: 'support' })
      .expect(201);
    const granted = await request(app)
      .post(`/admin/users/${ada.id}/roles`)
      .set(bearer(admin.tokens))
      .send({ role: 'support' })
      .expect(200);
    expect(granted.body.data.roles).toEqual(['support', 'user']);

    const refreshed = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: adaTokens.refreshToken })
      .expect(200);
    const claims = JSON.parse(
      Buffer.from(refreshed.body.data.accessToken.split('.')[1], 'base64url').toString(),
    );
    expect(claims.roles).toEqual(['support', 'user']);

    await request(app)
      .delete(`/admin/users/${ada.id}/roles/support`)
      .set(bearer(admin.tokens))
      .expect(200);
  });

  it('disabling a user ends their sessions until they are enabled again', async () => {
    const admin = await adminSession(app);
    const ada = await register(app, 'ada@example.com');
    const adaTokens = await login(app, 'ada@example.com');

    await request(app).post(`/admin/users/${ada.id}/disable`).set(bearer(admin.tokens)).expect(204);
    await request(app).get('/users/me').set(bearer(adaTokens)).expect(401);
    await request(app)
      .post('/auth/login')
      .send({ email: 'ada@example.com', password: 'correct horse battery staple' })
      .expect(401);

    await request(app).post(`/admin/users/${ada.id}/enable`).set(bearer(admin.tokens)).expect(204);
    await login(app, 'ada@example.com');
  });

  it('stops an admin from removing their own admin role or disabling themselves', async () => {
    const admin = await adminSession(app);
    await request(app)
      .delete(`/admin/users/${admin.user.id}/roles/admin`)
      .set(bearer(admin.tokens))
      .expect(409);
    await request(app)
      .post(`/admin/users/${admin.user.id}/disable`)
      .set(bearer(admin.tokens))
      .expect(409);
  });

  it('lists users with pagination, without password hashes', async () => {
    const admin = await adminSession(app);
    await register(app, 'ada@example.com');
    const res = await request(app)
      .get('/admin/users?pageSize=1')
      .set(bearer(admin.tokens))
      .expect(200);
    expect(res.body.meta).toEqual({ page: 1, pageSize: 1, total: 2, totalPages: 2 });
    expect(res.body.data[0]).not.toHaveProperty('passwordHash');
    const filtered = await request(app).get('/admin/users?email=ada').set(bearer(admin.tokens));
    expect(filtered.body.data.map((u: { email: string }) => u.email)).toEqual(['ada@example.com']);
  });

  it('exposes the dev email reader only when DEV_ENDPOINTS is on', async () => {
    await request(app).get('/dev/emails').expect(200);
    const production = createApp(buildContainer({ config: { DEV_ENDPOINTS: false } }));
    await request(production).get('/dev/emails').expect(404);
    expect(await getPrisma().devEmail.count()).toBe(0);
  });
});
