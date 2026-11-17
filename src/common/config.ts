import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((value) => value === 'true');

const configSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    TRUST_PROXY: bool.default(false),

    DATABASE_URL: z.string().url(),
    REDIS_URL: z.string().url(),

    /** Base64 of exactly 32 bytes: the AES-256-GCM key for data encrypted at rest. */
    KEY_ENCRYPTION_KEY: z
      .string()
      .refine((value) => Buffer.from(value, 'base64').length === 32, 'must be 32 bytes, base64'),

    JWT_ISSUER: z.string().url(),
    JWT_AUDIENCE: z.string().min(1).default('api'),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),

    KEY_STORE: z.enum(['local', 'kms']).default('local'),
    AWS_REGION: z.string().optional(),

    EMAIL_PROVIDER: z.enum(['fake', 'ses']).default('fake'),
    EMAIL_FROM: z.email(),
    APP_URL: z.string().url(),
    DEV_ENDPOINTS: bool.default(false),

    LOGIN_MAX_FAILURES_PER_ACCOUNT: z.coerce.number().int().min(1).default(5),
    LOGIN_MAX_FAILURES_PER_IP: z.coerce.number().int().min(1).default(20),
    LOGIN_THROTTLE_WINDOW_SECONDS: z.coerce.number().int().min(1).default(900),
  })
  .superRefine((env, ctx) => {
    if ((env.KEY_STORE === 'kms' || env.EMAIL_PROVIDER === 'ses') && !env.AWS_REGION) {
      ctx.addIssue({ code: 'custom', path: ['AWS_REGION'], message: 'required for kms or ses' });
    }
    if (env.DEV_ENDPOINTS && env.EMAIL_PROVIDER !== 'fake') {
      ctx.addIssue({
        code: 'custom',
        path: ['DEV_ENDPOINTS'],
        message: 'only allowed with EMAIL_PROVIDER=fake',
      });
    }
  });

export type Config = z.infer<typeof configSchema>;

/** Parses and validates env vars. Throws one error listing every problem, so startup fails fast. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = configSchema.safeParse(env);
  if (!result.success) {
    const problems = result.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${problems.join('\n')}`);
  }
  return result.data;
}

// Singleton: config is read once and shared, so every module sees the same validated values.
let cached: Config | undefined;
export function getConfig(): Config {
  cached ??= loadConfig();
  return cached;
}
