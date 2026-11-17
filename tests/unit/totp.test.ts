import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  matchTotp,
  totpCode,
} from '../../src/modules/mfa/totp';

// RFC 6238 Appendix B, SHA-1: the secret is the ASCII string "12345678901234567890".
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890'));
const RFC_VECTORS: [seconds: number, code: string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('TOTP (RFC 6238)', () => {
  it.each(RFC_VECTORS)('matches the RFC test vector at T=%i', (seconds, expected) => {
    expect(totpCode(RFC_SECRET, Math.floor(seconds / 30), 8)).toBe(expected);
  });

  it('round-trips base32 and generates 160-bit secrets', () => {
    expect(RFC_SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(base32Decode(RFC_SECRET).toString()).toBe('12345678901234567890');
    expect(base32Decode(generateTotpSecret())).toHaveLength(20);
  });

  it('accepts the current step and one either side, and returns which step matched', () => {
    const now = 1_700_000_000_000;
    const step = Math.floor(now / 1000 / 30);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step), now)).toBe(step);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), now)).toBe(step - 1);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), now)).toBe(step + 1);
    expect(matchTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 2), now)).toBeNull();
    expect(matchTotp(RFC_SECRET, 'abcdef', now)).toBeNull();
  });
});
