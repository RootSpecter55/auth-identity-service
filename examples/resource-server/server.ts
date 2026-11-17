/**
 * A minimal backend that trusts tokens from auth-identity-service. It knows only the JWKS URL:
 * no shared secret, no database, no call to the identity service per request. `jose` fetches
 * the public keys, caches them, and refetches when a token names a key it has not seen (after
 * a rotation).
 *
 *   JWKS_URL=http://localhost:3000/.well-known/jwks.json npm run example:resource-server
 *   curl localhost:4000/notes -H "Authorization: Bearer $ACCESS_TOKEN"
 */
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export type ResourceServerOptions = { jwksUrl: string; issuer: string; audience: string };

export function createResourceServer({ jwksUrl, issuer, audience }: ResourceServerOptions): Server {
  const jwks = createRemoteJWKSet(new URL(jwksUrl));

  async function authenticate(req: IncomingMessage): Promise<JWTPayload | null> {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ')) return null;
    try {
      const { payload } = await jwtVerify(header.slice(7), jwks, {
        issuer,
        audience,
        algorithms: ['ES256'], // never accept a token that names a different algorithm
      });
      return payload;
    } catch {
      return null; // bad signature, unknown key, expired, wrong issuer or audience
    }
  }

  return createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.url !== '/notes')
      return send(404, { error: { code: 'NOT_FOUND', message: 'Not found' } });

    const claims = await authenticate(req);
    if (!claims)
      return send(401, { error: { code: 'UNAUTHORIZED', message: 'Invalid or missing token' } });

    const roles = Array.isArray(claims.roles) ? claims.roles : [];
    send(200, { data: { notesFor: claims.sub, roles, adminView: roles.includes('admin') } });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? 4000);
  createResourceServer({
    jwksUrl: process.env.JWKS_URL ?? 'http://localhost:3000/.well-known/jwks.json',
    issuer: process.env.JWT_ISSUER ?? 'http://localhost:3000',
    audience: process.env.JWT_AUDIENCE ?? 'api',
  }).listen(port, () => console.log(`Resource server on port ${port}`));
}
