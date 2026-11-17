import { z } from 'zod';
import { paginationQuerySchema } from '../../common/pagination';
import { email } from '../users/users.schemas';

export const loginBody = z.object({ email, password: z.string().min(1).max(128) });

export const loginMfaBody = z
  .object({
    mfaToken: z.string().min(20).max(200),
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    recoveryCode: z.string().min(8).max(32).optional(),
  })
  .refine((body) => Boolean(body.code) !== Boolean(body.recoveryCode), 'send code or recoveryCode');

export const refreshBody = z.object({ refreshToken: z.string().min(20).max(200) });

export const sessionParams = z.object({ sessionId: z.uuid() });
export const listSessionsQuery = paginationQuerySchema;

export type LoginInput = z.infer<typeof loginBody>;
export type LoginMfaInput = z.infer<typeof loginMfaBody>;
export type RefreshInput = z.infer<typeof refreshBody>;
export type SessionParams = z.infer<typeof sessionParams>;
export type ListSessionsQuery = z.infer<typeof listSessionsQuery>;
