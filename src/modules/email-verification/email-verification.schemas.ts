import { z } from 'zod';

export const confirmEmailBody = z.object({ token: z.string().min(20).max(200) });

export type ConfirmEmailInput = z.infer<typeof confirmEmailBody>;
