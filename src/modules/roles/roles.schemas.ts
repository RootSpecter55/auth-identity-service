import { z } from 'zod';
import { paginationQuerySchema } from '../../common/pagination';

export const roleName = z
  .string()
  .min(2)
  .max(50)
  .regex(/^[a-z][a-z0-9_-]*$/, 'lowercase letters, digits, dashes and underscores');

export const createRoleBody = z.object({
  name: roleName,
  description: z.string().trim().max(200).default(''),
});

export const listRolesQuery = paginationQuerySchema;

export type CreateRoleInput = z.infer<typeof createRoleBody>;
export type ListRolesQuery = z.infer<typeof listRolesQuery>;
