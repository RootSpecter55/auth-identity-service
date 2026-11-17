/**
 * Measures login latency against a running API. argon2id is deliberately slow, so this shows
 * what one login costs on this machine and how it degrades under concurrency.
 *
 *   docker compose up --build
 *   npm run bench:login                          # 200 logins, 10 at a time
 *   LOGINS=1000 CONCURRENCY=50 API_URL=http://host:3000 npm run bench:login
 *
 * Creates one user, then logs in LOGINS times with the right password and prints latency
 * percentiles. Raise LOGIN_MAX_FAILURES_* if you also send failures: throttling would kick in.
 * Everything runs on one machine, so the numbers describe this setup only.
 */
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const API_URL = process.env.API_URL ?? 'http://localhost:3000';
const LOGINS = Number(process.env.LOGINS ?? 200);
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 10);
const PASSWORD = 'benchmark password long enough';

async function post(path: string, body: unknown): Promise<Response> {
  return fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] ?? 0;
}

async function main() {
  const email = `bench-${randomUUID()}@example.com`;
  const registered = await post('/users', { email, name: 'Bench', password: PASSWORD });
  if (registered.status !== 202) throw new Error(`register -> ${registered.status}`);

  const timings: number[] = [];
  let failures = 0;
  let next = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (next < LOGINS) {
        next++;
        const t0 = performance.now();
        const res = await post('/auth/login', { email, password: PASSWORD });
        await res.arrayBuffer();
        timings.push(performance.now() - t0);
        if (res.status !== 200) failures++;
      }
    }),
  );
  const seconds = (performance.now() - started) / 1000;
  const sorted = timings.sort((a, b) => a - b);

  console.log(`logins: ${LOGINS}, concurrency: ${CONCURRENCY}, failures: ${failures}`);
  console.log(`throughput: ${(LOGINS / seconds).toFixed(1)} logins/s`);
  for (const p of [50, 95, 99]) console.log(`p${p}: ${percentile(sorted, p).toFixed(0)} ms`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
