import { UnauthorizedError } from '../../src/common/errors';
import type { MfaService } from '../../src/modules/mfa/mfa.service';
import type { LoginThrottle } from '../../src/modules/sessions/login-throttle';
import type {
  RefreshTokenRepository,
  SessionRepository,
} from '../../src/modules/sessions/sessions.repository';
import { SessionsService } from '../../src/modules/sessions/sessions.service';
import type { TokensService } from '../../src/modules/tokens/tokens.service';
import type { UserRepository } from '../../src/modules/users/users.repository';
import { fakeDbContext, mockOf } from './fakes';

const client = { ipAddress: '203.0.113.9', userAgent: 'jest' };

describe('SessionsService', () => {
  let users: jest.Mocked<UserRepository>;
  let sessions: jest.Mocked<SessionRepository>;
  let refreshTokens: jest.Mocked<RefreshTokenRepository>;
  let throttle: jest.Mocked<LoginThrottle>;
  let service: SessionsService;

  beforeEach(() => {
    users = mockOf<UserRepository>('findByEmail', 'findById', 'roleNames');
    sessions = mockOf<SessionRepository>('revoke', 'create', 'touch');
    refreshTokens = mockOf<RefreshTokenRepository>('findByHash', 'rotate', 'create');
    throttle = mockOf<LoginThrottle>('check', 'recordFailure', 'reset');
    service = new SessionsService(
      fakeDbContext(),
      users,
      sessions,
      refreshTokens,
      mockOf<TokensService>('issueAccessToken'),
      mockOf<MfaService>('isEnabled'),
      throttle,
      30,
    );
  });

  it('counts a login for an unknown email as a failure and answers generically', async () => {
    users.findByEmail.mockResolvedValue(null);
    await expect(
      service.login({ email: 'x@example.com', password: 'whatever' }, client),
    ).rejects.toEqual(new UnauthorizedError('Invalid email or password'));
    expect(throttle.recordFailure).toHaveBeenCalledWith('x@example.com', '203.0.113.9');
  });

  it('revokes the family when a ROTATED refresh token is presented', async () => {
    refreshTokens.findByHash.mockResolvedValue({
      id: 'rt1',
      status: 'ROTATED',
      session: { id: 's1', userId: 'u1' },
    } as never);
    await expect(service.refresh('old-token-old-token-old')).rejects.toBeInstanceOf(
      UnauthorizedError,
    );
    expect(sessions.revoke).toHaveBeenCalledWith(expect.anything(), 's1', 'REFRESH_TOKEN_REUSE');
    expect(refreshTokens.create).not.toHaveBeenCalled();
  });

  it('revokes the family when it loses the compare-and-set to a concurrent refresh', async () => {
    refreshTokens.findByHash.mockResolvedValue({
      id: 'rt1',
      status: 'ACTIVE',
      session: { id: 's1', userId: 'u1' },
    } as never);
    refreshTokens.rotate.mockResolvedValue(false);
    await expect(service.refresh('raced-token-raced-token')).rejects.toBeInstanceOf(
      UnauthorizedError,
    );
    expect(sessions.revoke).toHaveBeenCalledWith(expect.anything(), 's1', 'REFRESH_TOKEN_REUSE');
  });

  it('does not treat an already REVOKED token as a new reuse event', async () => {
    refreshTokens.findByHash.mockResolvedValue({
      id: 'rt1',
      status: 'REVOKED',
      session: { id: 's1', userId: 'u1' },
    } as never);
    await expect(service.refresh('revoked-token-revoked-1')).rejects.toBeInstanceOf(
      UnauthorizedError,
    );
    expect(sessions.revoke).not.toHaveBeenCalled();
  });
});
