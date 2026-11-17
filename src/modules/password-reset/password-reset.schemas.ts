import { z } from 'zod';
import { email, password } from '../users/users.schemas';

export const requestResetBody = z.object({ email });
export const confirmResetBody = z.object({
  token: z.string().min(20).max(200),
  newPassword: password,
});

export type RequestResetInput = z.infer<typeof requestResetBody>;
export type ConfirmResetInput = z.infer<typeof confirmResetBody>;
