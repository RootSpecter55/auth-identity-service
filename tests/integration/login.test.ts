import request from 'supertest';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { adminSession, bearer, closeShared, PASSWORD, register, resetState } from './helpers';

const app = createApp();

beforeEach(resetState);
afterAll(closeShared);

function attempt(email: string, password: string) {
  return request(app).post('/auth/login').send({ email, password });
}

describe('login', () => {
  it('returns tokens with the user’s roles and email-verified state', async () => {
    await register(app, 'ada@example.com', false);
    const res = await attempt('ada@example.com', PASSWORD).expect(200);
    expect(res.body.data).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
    const claims = JSON.parse(
      Buffer.from(res.body.data.accessToken.split('.')[1], 'base64url').toString(),
    );
    expect(claims).toMatchObject({
      roles: ['user'],
      email_verified: false,
      aud: 'api',
      iss: 'http://localhost:3000',
    });
  });

  it('gives the same answer for an unknown email, a wrong password and a disabled account', async () => {
    await register(app, 'ada@example.com');
    const unknown = await attempt('nobody@example.com', PASSWORD);
    const wrong = await attempt('ada@example.com', 'wrong password!!');

    const { tokens } = await adminSession(app);
    const ada = await getPrisma().user.findUniqueOrThrow({ where: { email: 'ada@example.com' } });
    await request(app).post(`/admin/users/${ada.id}/disable`).set(bearer(tokens)).expect(204);
    const disabled = await attempt('ada@example.com', PASSWORD);

    for (const res of [unknown, wrong, disabled]) {
      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        error: { code: 'UNAUTHORIZED', message: 'Invalid email or password' },
      });
    }
  });

  it('locks an account after repeated failures, even against the right password', async () => {
    await register(app, 'ada@example.com');
    for (let i = 0; i < 3; i++) await attempt('ada@example.com', 'wrong password!!').expect(401);

    const locked = await attempt('ada@example.com', PASSWORD);
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('TOO_MANY_REQUESTS');
    expect(Number(locked.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(locked.headers['retry-after'])).toBeLessThanOrEqual(60);
  });

  it('throttles an unknown email exactly like a real one, so lockouts reveal nothing', async () => {
    for (let i = 0; i < 3; i++) await attempt('nobody@example.com', PASSWORD).expect(401);
    await attempt('nobody@example.com', PASSWORD).expect(429);
  });

  it('throttles an IP that tries many different accounts', async () => {
    // Per-IP limit is 10 in tests; each email stays under its own limit of 3.
    for (let i = 0; i < 10; i++) await attempt(`user${i}@example.com`, PASSWORD).expect(401);
    await attempt('someone-else@example.com', PASSWORD).expect(429);
  });

  it('a successful login resets the account counter', async () => {
    await register(app, 'ada@example.com');
    for (let i = 0; i < 2; i++) await attempt('ada@example.com', 'wrong password!!').expect(401);
    await attempt('ada@example.com', PASSWORD).expect(200);
    for (let i = 0; i < 2; i++) await attempt('ada@example.com', 'wrong password!!').expect(401);
    await attempt('ada@example.com', PASSWORD).expect(200);
  });
});

describe('registration', () => {
  it('answers the same for a new and an existing email, and stores an argon2id hash', async () => {
    const first = await request(app)
      .post('/users')
      .send({ email: 'Ada@Example.com', name: 'Ada', password: PASSWORD })
      .expect(202);
    const again = await request(app)
      .post('/users')
      .send({ email: 'ada@example.com', name: 'Someone', password: 'another long password' })
      .expect(202);
    expect(again.body).toEqual(first.body);

    const users = await getPrisma().user.findMany();
    expect(users).toHaveLength(1);
    expect(users[0]!.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);

    const emails = await getPrisma().devEmail.findMany({ orderBy: { createdAt: 'asc' } });
    expect(emails.map((e) => e.subject)).toEqual([
      'Confirm your email address',
      'Someone tried to register with your email',
    ]);
  });

  it('rejects short passwords and invalid emails', async () => {
    const res = await request(app)
      .post('/users')
      .send({ email: 'nope', name: '', password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error.details.map((d: { path: string }) => d.path).sort()).toEqual([
      'email',
      'name',
      'password',
    ]);
  });
});
