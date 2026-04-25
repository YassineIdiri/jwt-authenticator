import { Injectable } from '@angular/core';

/**
 * In-memory access token store.
 *
 * WHY MEMORY:
 *   localStorage / sessionStorage are readable by any JavaScript on the page
 *   (XSS attack → token theft → attacker uses token from anywhere).
 *   Memory is not accessible cross-origin or by injected scripts.
 *
 * TRADE-OFF:
 *   The token is lost on page refresh. This is intentional — the refresh
 *   token cookie (HttpOnly, set by the backend) is used to silently obtain
 *   a new access token on startup via AuthService.initAuth().
 *
 * NOTE on the senior's suggestion (HttpOnly cookie for access token too):
 *   If the backend is updated to issue the access token as an HttpOnly cookie,
 *   this store becomes unused and the interceptor reads nothing from JS.
 *   That change requires CSRF protection (Double Submit Cookie pattern) and
 *   the backend filter reading from cookies instead of Authorization header.
 *   This store is kept for the current architecture.
 */
@Injectable({ providedIn: 'root' })
export class TokenStore {

  private token: string | null = null;

  get(): string | null {
    return this.token;
  }

  set(token: string): void {
    this.token = token;
  }

  clear(): void {
    this.token = null;
  }

  has(): boolean {
    return this.token !== null;
  }
}
