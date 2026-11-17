import { z } from 'zod';
import { paginationQuerySchema } from '../../common/pagination';
import { roleName } from '../roles/roles.schemas';

export const userParams = z.object({ userId: z.uuid() });
export const userRoleParams = userParams.extend({ role: roleName });
export const grantRoleBody = z.object({ role: roleName });
export const listUsersQuery = paginationQuerySchema.extend({
  email: z.string().min(1).max(254).optional(),
});
export const listKeysQuery = paginationQuerySchema;

export type UserParams = z.infer<typeof userParams>;
export type UserRoleParams = z.infer<typeof userRoleParams>;
export type GrantRoleInput = z.infer<typeof grantRoleBody>;
export type ListUsersQuery = z.infer<typeof listUsersQuery>;
export type ListKeysQuery = z.infer<typeof listKeysQuery>;
