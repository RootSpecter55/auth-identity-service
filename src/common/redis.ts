import { Redis } from 'ioredis';
import { getConfig } from './config';

// Singleton: one connection for the process (only login throttling uses Redis).
let client: Redis | undefined;
export function getRedis(): Redis {
  client ??= new Redis(getConfig().REDIS_URL, {
    // Fail a command after one reconnect attempt instead of queueing it indefinitely.
    maxRetriesPerRequest: 1,
  });
  return client;
}
