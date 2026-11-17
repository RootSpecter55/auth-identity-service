import { loadConfig } from '../../src/common/config';

const base = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  REDIS_URL: 'redis://localhost:6379/0',
  KEY_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64'),
  JWT_ISSUER: 'https://id.example.com',
  EMAIL_FROM: 'no-reply@example.com',
  APP_URL: 'https://app.example.com',
};

describe('loadConfig', () => {
  it('applies defaults: local keys, fake email, dev endpoints off', () => {
    expect(loadConfig(base)).toMatchObject({
      KEY_STORE: 'local',
      EMAIL_PROVIDER: 'fake',
      DEV_ENDPOINTS: false,
      ACCESS_TOKEN_TTL_SECONDS: 900,
    });
  });

  it('requires a 32-byte encryption key', () => {
    expect(() =>
      loadConfig({ ...base, KEY_ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') }),
    ).toThrow(/KEY_ENCRYPTION_KEY: must be 32 bytes/);
  });

  it('refuses dev endpoints with a real email provider, and needs a region for AWS providers', () => {
    expect(() =>
      loadConfig({
        ...base,
        EMAIL_PROVIDER: 'ses',
        AWS_REGION: 'eu-west-1',
        DEV_ENDPOINTS: 'true',
      }),
    ).toThrow(/DEV_ENDPOINTS: only allowed with EMAIL_PROVIDER=fake/);
    expect(() => loadConfig({ ...base, KEY_STORE: 'kms' })).toThrow(
      /AWS_REGION: required for kms or ses/,
    );
  });

  it('lists every missing variable in one error', () => {
    expect(() => loadConfig({})).toThrow(
      /DATABASE_URL[\s\S]*REDIS_URL[\s\S]*KEY_ENCRYPTION_KEY[\s\S]*JWT_ISSUER/,
    );
  });
});
