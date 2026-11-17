import type { Redis } from 'ioredis';
import { sha256 } from '../../common/crypto';
import { TooManyRequestsError } from '../../common/errors';

export type ThrottleLimits = { perAccount: number; perIp: number; windowSeconds: number };

/**
 * Fixed-window counters of failed logins in Redis: one per account (keyed by a hash of the
 * email, so even unknown emails get locked out the same way) and one per client IP.
 * INCR + EXPIRE on the first failure starts the window; the key expiring ends it.
 */
export class LoginThrottle {
  constructor(
    private readonly redis: Redis,
    private readonly limits: ThrottleLimits,
  ) {}

  private keys(email: string, ip: string) {
    return { account: `login:fail:account:${sha256(email)}`, ip: `login:fail:ip:${ip}` };
  }

  /** Throws 429 (with Retry-After) if either counter is at its limit. */
  async check(email: string, ip: string): Promise<void> {
    const keys = this.keys(email, ip);
    const [account, byIp] = await this.redis.mget(keys.account, keys.ip);
    const blocked =
      Number(account ?? 0) >= this.limits.perAccount
        ? keys.account
        : Number(byIp ?? 0) >= this.limits.perIp
          ? keys.ip
          : null;
    if (blocked) {
      const ttl = await this.redis.ttl(blocked);
      throw new TooManyRequestsError(ttl > 0 ? ttl : this.limits.windowSeconds);
    }
  }

  async recordFailure(email: string, ip: string): Promise<void> {
    const keys = this.keys(email, ip);
    await this.redis
      .multi()
      .incr(keys.account)
      .expire(keys.account, this.limits.windowSeconds, 'NX')
      .incr(keys.ip)
      .expire(keys.ip, this.limits.windowSeconds, 'NX')
      .exec();
  }

  /** A successful login clears the account's counter. The IP counter keeps counting. */
  async reset(email: string, ip: string): Promise<void> {
    await this.redis.del(this.keys(email, ip).account);
  }
}
