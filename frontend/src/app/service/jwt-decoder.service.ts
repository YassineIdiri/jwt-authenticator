import { Injectable } from '@angular/core';

export interface JwtPayload {
  sub:   string;       // username
  roles: string[];     // ex: ['ROLE_USER'] ou ['ROLE_ADMIN']
  iat:   number;
  exp:   number;
}

@Injectable({ providedIn: 'root' })
export class JwtDecoderService {

  decode(token: string): JwtPayload | null {
    if (!token) return null;

    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      // ✅ Fix base64url → base64 standard
      // Les JWT utilisent base64url ('-' et '_')
      // mais atob() attend du base64 standard ('+' et '/')
      const base64 = parts[1]
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(parts[1].length + (4 - parts[1].length % 4) % 4, '=');

      return JSON.parse(atob(base64)) as JwtPayload;
    } catch {
      return null;
    }
  }

  isExpired(token: string): boolean {
    const payload = this.decode(token);
    if (!payload) return true;
    return payload.exp < Date.now() / 1000;
  }

  // Retourne le temps restant en millisecondes
  getTimeUntilExpiration(token: string): number {
    const payload = this.decode(token);
    if (!payload) return 0;
    return Math.max(0, (payload.exp - Date.now() / 1000) * 1000);
  }
}
