import { PrismaPg } from '@prisma/adapter-pg';
import 'dotenv/config';
import { PrismaClient } from '../src/generated/prisma/client';

/** The two built-in roles. Idempotent, so it is safe to run on every deploy. */
const ROLES = [
  { name: 'user', description: 'Every registered user' },
  { name: 'admin', description: 'Manages users, roles and signing keys' },
];

async function main() {
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL! }),
  });
  for (const role of ROLES) {
    await prisma.role.upsert({ where: { name: role.name }, update: {}, create: role });
  }
  await prisma.$disconnect();
  console.log(`Seeded roles: ${ROLES.map((r) => r.name).join(', ')}`);
}

void main();
