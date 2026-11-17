import request from 'supertest';
import { createApp } from '../../src/app';
import { getPrisma } from '../../src/common/db';
import { timeStep, totpCode } from '../../src/modules/mfa/totp';
import { bearer, closeShared, login, PASSWORD, register, resetState, type Tokens } from './helpers';

const app = createApp();
const email = 'ada@example.com';
let tokens: Tokens;

/** The code for `offset` steps from now (the server accepts the current step ±1). */
function code(secret: string, offset = 0) {
  return totpCode(secret, timeStep(Date.now()) + offset);
}

async function enableMfa() {
  const enrolled = await request(app).post('/mfa/totp/enroll').set(bearer(tokens)).expect(201);
  const { secret, otpauthUri } = enrolled.body.data;
  expect(otpauthUri).toMatch(/^otpauth:\/\/totp\/localhost%3A3000%3Aada%40example\.com\?secret=/);
  const activated = await request(app)
    .post('/mfa/totp/activate')
    .set(bearer(tokens))
    .send({ code: code(secret) })
    .expect(200);
  return { secret: secret as string, recoveryCodes: activated.body.data.recoveryCodes as string[] };
}

async function passwordStep() {
  const res = await request(app)
    .post('/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200);
  expect(res.body.data).toEqual({ mfaRequired: true, mfaToken: expect.any(String) });
  return res.body.data.mfaToken as string;
}

beforeEach(async () => {
  await resetState();
  await register(app, email);
  tokens = await login(app, email);
});
afterAll(closeShared);

describe('TOTP MFA', () => {
  it('enrols, then requires a code at login', async () => {
    const { secret, recoveryCodes } = await enableMfa();
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);

    const stored = await getPrisma().totpFactor.findFirstOrThrow();
    expect(stored.status).toBe('ACTIVE');
    expect(stored.secretEncrypted).not.toContain(secret);
    const hashes = await getPrisma().recoveryCode.findMany();
    expect(hashes.map((h) => h.codeHash)).not.toContain(recoveryCodes[0]);

    const mfaToken = await passwordStep();
    // The activation used the current step, so log in with the next one.
    const res = await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken, code: code(secret, 1) })
      .expect(200);
    await request(app).get('/users/me').set(bearer(res.body.data)).expect(200);
  });

  it('rejects a code that was already used (no replay)', async () => {
    const { secret } = await enableMfa();
    const used = code(secret, 1);
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken: await passwordStep(), code: used })
      .expect(200);
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken: await passwordStep(), code: used })
      .expect(401);
    // The step of the activation code is also spent.
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken: await passwordStep(), code: code(secret) })
      .expect(401);
  });

  it('accepts each recovery code once, ignoring case and dashes', async () => {
    const { recoveryCodes } = await enableMfa();
    const recoveryCode = recoveryCodes[0]!.toUpperCase().replace(/-/g, '');
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken: await passwordStep(), recoveryCode })
      .expect(200);
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken: await passwordStep(), recoveryCode })
      .expect(401);
  });

  it('allows only five attempts per challenge, then refuses even a correct code', async () => {
    const { secret } = await enableMfa();
    const mfaToken = await passwordStep();
    for (let i = 0; i < 5; i++) {
      await request(app).post('/auth/login/mfa').send({ mfaToken, code: '000000' }).expect(401);
    }
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken, code: code(secret, 1) })
      .expect(401);
  });

  it('rejects an expired challenge and a wrong activation code', async () => {
    await request(app).post('/mfa/totp/enroll').set(bearer(tokens)).expect(201);
    await request(app)
      .post('/mfa/totp/activate')
      .set(bearer(tokens))
      .send({ code: '123456' })
      .expect(401);
    const enrolled = await request(app).post('/mfa/totp/enroll').set(bearer(tokens)).expect(201);
    await request(app)
      .post('/mfa/totp/activate')
      .set(bearer(tokens))
      .send({ code: code(enrolled.body.data.secret) })
      .expect(200);

    const mfaToken = await passwordStep();
    await getPrisma().mfaChallenge.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    await request(app)
      .post('/auth/login/mfa')
      .send({ mfaToken, code: code(enrolled.body.data.secret, 1) })
      .expect(401);
  });

  it('disables MFA with a fresh code, after which a password is enough again', async () => {
    const { secret } = await enableMfa();
    await request(app)
      .post('/mfa/totp/disable')
      .set(bearer(tokens))
      .send({ code: code(secret, 1) })
      .expect(204);
    const res = await request(app)
      .post('/auth/login')
      .send({ email, password: PASSWORD })
      .expect(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));
    expect(await getPrisma().recoveryCode.count()).toBe(0);
  });
});
