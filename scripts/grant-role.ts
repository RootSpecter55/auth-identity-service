/**
 * Grants a role to an existing user, e.g. to create the first admin:
 *
 *   npm run admin:grant -- ada@example.com admin
 */
import 'dotenv/config';
import { getPrisma } from '../src/common/db';
import { RoleRepository } from '../src/modules/roles/roles.repository';

async function main() {
  const [email, role = 'admin'] = process.argv.slice(2);
  if (!email) {
    console.error('Usage: npm run admin:grant -- <email> [role]');
    process.exit(1);
  }
  const prisma = getPrisma();
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (!user) {
    console.error(`No user with email ${email}`);
    process.exit(1);
  }
  await new RoleRepository().grant(prisma, user.id, role);
  console.log(`Granted ${role} to ${email}. It appears in their token at the next refresh.`);
  await prisma.$disconnect();
}

void main();
