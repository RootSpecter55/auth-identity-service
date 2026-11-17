import request from 'supertest';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { bearer, closeShared, login, register, resetState, tokenFromLatestEmail } from './helpers';

const app = createApp();
const email = 'ada@example.com';

beforeEach(resetState);
afterAll(closeShared);

describe('email verification', () => {
  it('verifies with the emailed token, once', async () => {
    await register(app, email, false);
    const token = await tokenFromLatestEmail(email);
    expect((await getPrisma().emailToken.findFirstOrThrow()).tokenHash).not.toBe(token);

    await request(app).post('/email-verification/confirm').send({ token }).expect(204);
    await request(app).post('/email-verification/confirm').send({ token }).expect(401);
    const user = await getPrisma().user.findUniqueOrThrow({ where: { email } });
    expect(user.emailVerifiedAt).not.toBeNull();
  });

  it('resends to unverified users only, and rejects expired links', async () => {
    await register(app, email, false);
    const tokens = await login(app, email);
    await getPrisma().emailToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    await request(app)
      .post('/email-verification/confirm')
      .send({ token: await tokenFromLatestEmail(email) })
      .expect(401);

    await request(app).post('/email-verification/resend').set(bearer(tokens)).expect(202);
    await request(app)
      .post('/email-verification/confirm')
      .send({ token: await tokenFromLatestEmail(email) })
      .expect(204);
    await request(app).post('/email-verification/resend').set(bearer(tokens)).expect(409);
  });
});

describe('password reset', () => {
  it('answers the same for unknown emails and sends nothing to them', async () => {
    await register(app, email);
    const known = await request(app).post('/password-reset/request').send({ email }).expect(202);
    const unknown = await request(app)
      .post('/password-reset/request')
      .send({ email: 'nobody@example.com' })
      .expect(202);
    expect(unknown.body).toEqual(known.body);
    expect(await getPrisma().devEmail.count({ where: { to: 'nobody@example.com' } })).toBe(0);
  });

  it('sets the new password, signs out every session and works only once', async () => {
    await register(app, email);
    const session = await login(app, email);
    await request(app).post('/password-reset/request').send({ email }).expect(202);
    const token = await tokenFromLatestEmail(email);

    await request(app)
      .post('/password-reset/confirm')
      .send({ token, newPassword: 'a brand new password' })
      .expect(204);
    await request(app).get('/users/me').set(bearer(session)).expect(401);
    await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: session.refreshToken })
      .expect(401);
    await login(app, email, 'a brand new password');
    await request(app)
      .post('/auth/login')
      .send({ email, password: 'correct horse battery staple' })
      .expect(401);

    await request(app)
      .post('/password-reset/confirm')
      .send({ token, newPassword: 'yet another password' })
      .expect(401);
  });

  it('a newer reset request invalidates older links', async () => {
    await register(app, email);
    await request(app).post('/password-reset/request').send({ email }).expect(202);
    const older = await tokenFromLatestEmail(email);
    await request(app).post('/password-reset/request').send({ email }).expect(202);

    await request(app)
      .post('/password-reset/confirm')
      .send({ token: older, newPassword: 'a brand new password' })
      .expect(401);
  });
});
