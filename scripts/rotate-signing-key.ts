/**
 * Rotates the JWT signing key (same as POST /admin/keys/rotate). Run on a schedule, e.g. monthly.
 *
 *   npm run keys:rotate
 */
import 'dotenv/config';
import { getPrisma } from '../src/common/db';
import { getRedis } from '../src/common/redis';
import { buildContainer } from '../src/container';

async function main() {
  const result = await buildContainer().services.tokens.rotate();
  console.log(
    `New signing key ${result.kid}. ${result.previousKid} stays in the JWKS until ${result.previousPublishedUntil.toISOString()}.`,
  );
  await getPrisma().$disconnect();
  await getRedis().quit();
}

void main();
