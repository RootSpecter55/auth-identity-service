import { z } from 'zod';
import { paginationQuerySchema } from '../../common/pagination';

export const listDevEmailsQuery = paginationQuerySchema.extend({
  to: z
    .email()
    .transform((value) => value.toLowerCase())
    .optional(),
});

export type ListDevEmailsQuery = z.infer<typeof listDevEmailsQuery>;
