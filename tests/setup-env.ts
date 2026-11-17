// Test environment: runs before every test file, before any app module reads config.
// Uses a separate database and Redis db index so tests never touch local development data.
Object.assign(process.env, {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  DATABASE_URL:
    process.env.TEST_DATABASE_URL ?? 'postgresql://app:app@localhost:5448/identity_test',
  REDIS_URL: process.env.TEST_REDIS_URL ?? 'redis://localhost:6383/1',
  KEY_ENCRYPTION_KEY: Buffer.from('test-only-key-32-bytes-long-abc!').toString('base64'),
  JWT_ISSUER: 'http://localhost:3000',
  JWT_AUDIENCE: 'api',
  ACCESS_TOKEN_TTL_SECONDS: '900',
  REFRESH_TOKEN_TTL_DAYS: '30',
  KEY_STORE: 'local',
  EMAIL_PROVIDER: 'fake',
  EMAIL_FROM: 'no-reply@example.com',
  APP_URL: 'http://localhost:3000',
  DEV_ENDPOINTS: 'true',
  LOGIN_MAX_FAILURES_PER_ACCOUNT: '3',
  LOGIN_MAX_FAILURES_PER_IP: '10',
  LOGIN_THROTTLE_WINDOW_SECONDS: '60',
});
