import { z } from 'zod';

export const email = z
  .email()
  .max(254)
  .transform((value) => value.toLowerCase());

/** Length is what matters most (NIST 800-63B); argon2 input is capped to keep hashing cheap. */
export const password = z.string().min(12, 'at least 12 characters').max(128);

export const registerBody = z.object({
  email,
  name: z.string().trim().min(1).max(100),
  password,
});

export const updateMeBody = z.object({ name: z.string().trim().min(1).max(100) });

export const changePasswordBody = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: password,
});

export type RegisterInput = z.infer<typeof registerBody>;
export type UpdateMeInput = z.infer<typeof updateMeBody>;
export type ChangePasswordInput = z.infer<typeof changePasswordBody>;
