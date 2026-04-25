import { Injectable } from '@angular/core';
import { JwtPayload } from '../models/auth.models';

/**
 * Decodes JWT access tokens client-side for reading claims.
 *
 * IMPORTANT: This is NOT verification — we trust the token because
 * it came from our backend over HTTPS. Verification happens server-side.
 * We decode only to read exp, roles, jti etc. for UI decisions.
 */
@Injectable({ providedIn: 'root' })
export class JwtDecoderService {

  decode(token: string): JwtPayload | null {
    if (!token) return null;

    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      // JWT uses base64url encoding ('-' and '_')
      // atob() requires standard base64 ('+' and '/')
      // Padding: base64 requires length % 4 === 0
      const base64url = parts[1];
      const base64    = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');

      const padded = base64.padEnd(
        base64.length + (4 - base64.length % 4) % 4,
        '='
      );

      return JSON.parse(atob(padded)) as JwtPayload;

    } catch {
      return null;
    }
  }

  /**
   * Returns true if the token is expired or undecodable.
   * Adds a 10-second buffer to account for clock skew between
   * client and server — avoids sending a token that expires
   * in flight before the server validates it.
   */
  isExpired(token: string, clockSkewSeconds = 10): boolean {
    const payload = this.decode(token);
    if (!payload) return true;
    return payload.exp < (Date.now() / 1000) + clockSkewSeconds;
  }

  /** Returns milliseconds until the token expires (0 if already expired). */
  getTimeUntilExpiration(token: string): number {
    const payload = this.decode(token);
    if (!payload) return 0;
    return Math.max(0, (payload.exp - Date.now() / 1000) * 1000);
  }

  /** Extracts the first role, stripping the 'ROLE_' prefix. */
  getRole(token: string): string | null {
    const payload = this.decode(token);
    if (!payload?.roles?.length) return null;
    return payload.roles[0].replace('ROLE_', '');
  }

  /** Returns the jti claim — used for token blacklist checks if needed. */
  getJti(token: string): string | null {
    return this.decode(token)?.jti ?? null;
  }
}
