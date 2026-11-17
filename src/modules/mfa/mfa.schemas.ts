import { z } from 'zod';

export const totpCodeBody = z.object({ code: z.string().regex(/^\d{6}$/, 'a 6-digit code') });

export type TotpCodeInput = z.infer<typeof totpCodeBody>;
