import type { Express } from 'express';
import request from 'supertest';
import { getPrisma } from '../../src/common/db';
import { getRedis } from '../../src/common/redis';

export const PASSWORD = 'correct horse battery staple';

/** Empties every table, keeping only the seeded roles, and clears the throttling counters. */
export async function resetState() {
  await getPrisma().$executeRawUnsafe(
    'TRUNCATE users, sessions, refresh_tokens, signing_keys, totp_factors, recovery_codes, mfa_challenges, email_tokens, dev_emails CASCADE',
  );
  await getPrisma().role.deleteMany({ where: { name: { notIn: ['user', 'admin'] } } });
  await getRedis().flushdb();
}

export async function closeShared() {
  await getPrisma().$disconnect();
  await getRedis().quit();
}

/** The token from the newest link emailed to `to` (the fake provider stores emails). */
export async function tokenFromLatestEmail(to: string): Promise<string> {
  const email = await getPrisma().devEmail.findFirstOrThrow({
    where: { to },
    orderBy: { createdAt: 'desc' },
  });
  const match = /token=([A-Za-z0-9_-]+)/.exec(email.text);
  if (!match) throw new Error(`No token in email: ${email.text}`);
  return match[1]!;
}

export type Tokens = { accessToken: string; refreshToken: string; sessionId: string };

export async function register(app: Express, email: string, verify = true) {
  await request(app)
    .post('/users')
    .send({ email, name: 'Test User', password: PASSWORD })
    .expect(202);
  if (verify) {
    const token = await tokenFromLatestEmail(email);
    await request(app).post('/email-verification/confirm').send({ token }).expect(204);
  }
  return getPrisma().user.findUniqueOrThrow({ where: { email } });
}

export async function login(app: Express, email: string, password = PASSWORD): Promise<Tokens> {
  const res = await request(app).post('/auth/login').send({ email, password }).expect(200);
  return res.body.data;
}

export function bearer(tokens: Pick<Tokens, 'accessToken'>) {
  return { Authorization: `Bearer ${tokens.accessToken}` };
}

/** Registers a user, grants admin directly in the database, and logs in (so the token has it). */
export async function adminSession(app: Express, email = 'admin@example.com') {
  const user = await register(app, email);
  const role = await getPrisma().role.findUniqueOrThrow({ where: { name: 'admin' } });
  await getPrisma().userRole.create({ data: { userId: user.id, roleId: role.id } });
  return { user, tokens: await login(app, email) };
}
