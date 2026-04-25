import { Injectable, inject, signal, computed } from '@angular/core';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { filter, take, tap } from 'rxjs/operators';
import { toObservable } from '@angular/core/rxjs-interop';

import { AuthApiService }   from './auth-api.service';
import { TokenStore }       from './token-store.service';
import { JwtDecoderService } from './jwt-decoder.service';
import { RegisterRequest, RegisterResponse, LoginRequest, AuthResponse } from '../models/auth.models';
import { environment } from '../../environments/environment';

/**
 * Central authentication state manager.
 *
 * Enterprise improvements over the original:
 *
 *  1. console.log removed — debug logging has no place in a service.
 *     Use browser devtools or a logging service if needed.
 *
 *  2. localStorage.setItem('username') removed.
 *     Storing anything auth-related in localStorage contradicts the
 *     memory-only strategy. Username is derived from the in-memory token
 *     via JwtDecoderService — no persistence needed.
 *     If you need the username after a page refresh, it comes back
 *     automatically via initAuth() → refresh → token decode.
 *
 *  3. getApiBaseUrl() replaced by environment.apiUrl.
 *     (window as any).__apiUrl was a runtime hack with no type safety.
 *     environment.ts is the Angular-idiomatic way to handle this.
 *
 *  4. getUserRole() and isLoggedIn() now delegate to JwtDecoderService
 *     instead of duplicating decode logic.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {

  private authApi     = inject(AuthApiService);
  private tokenStore  = inject(TokenStore);
  private jwtDecoder  = inject(JwtDecoderService);
  private router      = inject(Router);

  // ─────────────────────────────────────────────────────
  //  Private writable signals
  // ─────────────────────────────────────────────────────

  private _isAuthenticated = signal<boolean>(false);
  private _username        = signal<string | null>(null);
  private _isReady         = signal<boolean>(false);

  // ─────────────────────────────────────────────────────
  //  Public readonly signals — components bind to these
  // ─────────────────────────────────────────────────────

  isAuthenticated = this._isAuthenticated.asReadonly();
  username        = this._username.asReadonly();
  isReady         = this._isReady.asReadonly();

  // Computed signals — automatically derived, no manual updates needed
  isAdmin = computed(() => this.getUserRole() === 'ADMIN');
  isUser  = computed(() => this.getUserRole() === 'USER');

  // Observable bridge for the interceptor (needs Observable, not Signal)
  isAuthenticated$ = toObservable(this._isAuthenticated);

  // ─────────────────────────────────────────────────────
  //  Initialisation — called once at app startup
  // ─────────────────────────────────────────────────────

  constructor() {
    this.initAuth();
  }

  /**
   * Silently refreshes the access token on startup using the HttpOnly
   * refresh token cookie. If the cookie is absent or expired, the user
   * is treated as logged out — no redirect, no error shown.
   *
   * FIX: console.log removed. The try/error flow is silent by design —
   * a failed refresh on startup just means the user isn't authenticated.
   */
  private initAuth(): void {
    this.authApi.refresh().subscribe({
      next: (res) => {
        this.applySession(res);
        this._isReady.set(true);
      },
      error: () => {
        // Refresh failed = no valid session. Clear and continue — not an error.
        this.clearSession();
        this._isReady.set(true);
      }
    });
  }

  /**
   * Returns a Promise that resolves when initAuth() has completed.
   * Guards and the interceptor use this to avoid acting before
   * the initial auth state is known.
   */
  waitForReady(): Promise<void> {
    if (this._isReady()) return Promise.resolve();

    return new Promise(resolve => {
      toObservable(this._isReady)
        .pipe(filter(r => r), take(1))
        .subscribe(() => resolve());
    });
  }

  // ─────────────────────────────────────────────────────
  //  Auth operations
  // ─────────────────────────────────────────────────────

  register(req: RegisterRequest): Observable<RegisterResponse> {
    return this.authApi.register(req);
  }

  login(req: LoginRequest): Observable<AuthResponse> {
    return this.authApi.login(req).pipe(
      tap(res => this.applySession(res))
    );
  }

  /** Called by the interceptor on 401 to transparently refresh the session. */
  refreshToken(): Observable<AuthResponse> {
    return this.authApi.refresh().pipe(
      tap(res => this.applySession(res))
    );
  }

  logout(): Observable<void> {
    return this.authApi.logout().pipe(
      tap(() => this.clearSession())
    );
  }

  logoutAll(): Observable<void> {
    return this.authApi.logoutAll().pipe(
      tap(() => this.clearSession())
    );
  }

  /** Called by the interceptor when refresh itself fails — forces re-login. */
  logoutAndRedirect(reason: string = 'session_expired'): void {
    this.clearSession();
    this.router.navigate(['/login'], { queryParams: { reason } });
  }

  // ─────────────────────────────────────────────────────
  //  OAuth2
  // ─────────────────────────────────────────────────────

  initiateGoogleLogin(): void {
    // Full redirect to Spring — starts the Google OAuth2 flow
    window.location.href = `${environment.apiUrl}/oauth2/authorization/google`;
  }

  handleOAuth2Callback(code: string): Observable<AuthResponse> {
    return this.authApi.exchangeOAuth2Code(code).pipe(
      tap(res => this.applySession(res))
    );
  }

  // ─────────────────────────────────────────────────────
  //  Helpers
  // ─────────────────────────────────────────────────────

  getToken(): string | null {
    return this.tokenStore.get();
  }

  isLoggedIn(): boolean {
    const token = this.tokenStore.get();
    if (!token) return false;
    return !this.jwtDecoder.isExpired(token);
  }

  getUserRole(): string | null {
    const token = this.tokenStore.get();
    if (!token) return null;
    return this.jwtDecoder.getRole(token);
  }

  clearSession(): void {
    this.tokenStore.clear();
    this._isAuthenticated.set(false);
    this._username.set(null);
    // FIX: localStorage.removeItem('username') removed —
    // we no longer write username to localStorage.
  }

  // ─────────────────────────────────────────────────────
  //  Private
  // ─────────────────────────────────────────────────────

  /**
   * Applies a successful auth response to the in-memory state.
   * Single place that updates token + signals — no duplication across
   * login / refresh / OAuth2 exchange.
   *
   * FIX: localStorage.setItem('username') removed.
   * Username comes from the token itself on every decode — no need to
   * persist it. After a page refresh, initAuth() calls /refresh and
   * re-populates _username from the new token.
   */
  private applySession(res: AuthResponse): void {
    this.tokenStore.set(res.accessToken);
    this._username.set(res.username);
    this._isAuthenticated.set(true);
  }
}
