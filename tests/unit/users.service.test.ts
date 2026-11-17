import type { User } from '../../src/generated/prisma/client';
import type { EmailVerificationService } from '../../src/modules/email-verification/email-verification.service';
import type { RoleRepository } from '../../src/modules/roles/roles.repository';
import type { SessionRepository } from '../../src/modules/sessions/sessions.repository';
import type { UserRepository } from '../../src/modules/users/users.repository';
import { REGISTERED_MESSAGE, UsersService } from '../../src/modules/users/users.service';
import type { EmailProvider } from '../../src/providers/email';
import { fakeDbContext, mockOf } from './fakes';

describe('UsersService.register', () => {
  let users: jest.Mocked<UserRepository>;
  let verification: jest.Mocked<EmailVerificationService>;
  let email: jest.Mocked<EmailProvider>;
  let service: UsersService;
  const input = { email: 'ada@example.com', name: 'Ada', password: 'a long enough password' };

  beforeEach(() => {
    users = mockOf<UserRepository>('findByEmail', 'create');
    verification = mockOf<EmailVerificationService>('send');
    email = mockOf<EmailProvider>('send');
    service = new UsersService(
      fakeDbContext(),
      users,
      mockOf<RoleRepository>('grant'),
      mockOf<SessionRepository>('revokeAllForUser'),
      verification,
      email,
    );
  });

  it('for an existing email: creates nothing, tells the owner, and answers as for a new one', async () => {
    users.findByEmail.mockResolvedValue({ id: 'u1', email: input.email } as User);
    expect(await service.register(input)).toEqual({ message: REGISTERED_MESSAGE });
    expect(users.create).not.toHaveBeenCalled();
    expect(email.send).toHaveBeenCalledWith(expect.objectContaining({ to: input.email }));
  });

  it('for a new email: creates the user with an argon2id hash and sends a verification link', async () => {
    users.findByEmail.mockResolvedValue(null);
    users.create.mockResolvedValue({ id: 'u1', email: input.email } as User);
    expect(await service.register(input)).toEqual({ message: REGISTERED_MESSAGE });
    expect(users.create.mock.calls[0]![1].passwordHash).toMatch(/^\$argon2id\$/);
    expect(verification.send).toHaveBeenCalled();
  });
});
