import { Injectable, inject, signal, computed } from '@angular/core';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { filter, take, tap } from 'rxjs/operators';
import { toObservable } from '@angular/core/rxjs-interop';

import { AuthApiService} from './auth-api.service';
import { TokenStore } from './token-store.service';
import { JwtDecoderService } from './jwt-decoder.service';
import { RegisterRequest, RegisterResponse, LoginRequest, AuthResponse } from '../models/auth.models';

@Injectable({ providedIn: 'root' })
export class AuthService {

  private authApi    = inject(AuthApiService);
  private tokenStore = inject(TokenStore);
  private jwtDecoder = inject(JwtDecoderService);
  private router     = inject(Router);

  // ─────────────────────────────────────────────────────
  //  État global → signals privés en écriture
  // ─────────────────────────────────────────────────────

  private _isAuthenticated = signal<boolean>(false);
  private _username        = signal<string | null>(null);
  private _isReady         = signal<boolean>(false);

  // ─────────────────────────────────────────────────────
  //  Exposés en readonly aux composants
  // ─────────────────────────────────────────────────────

  isAuthenticated = this._isAuthenticated.asReadonly();
  username        = this._username.asReadonly();
  isReady         = this._isReady.asReadonly();

  // Computed : dérivés automatiquement du signal username/token
  isAdmin = computed(() => this.getUserRole() === 'ADMIN');
  isUser  = computed(() => this.getUserRole() === 'USER');

  // ✅ Compatibilité Observable pour l'interceptor (qui en a besoin)
  isAuthenticated$ = toObservable(this._isAuthenticated);

  // ─────────────────────────────────────────────────────
  //  Initialisation au démarrage de l'app
  // ─────────────────────────────────────────────────────

  constructor() {
    this.initAuth();
  }

private initAuth(): void {
  console.log('🚀 initAuth démarré');

  this.authApi.refresh().subscribe({
    next: (res) => {
      console.log('✅ refresh OK', res);
      this.tokenStore.set(res.accessToken);
      this._username.set(res.username);
      this._isAuthenticated.set(true);
      this._isReady.set(true);
      localStorage.setItem('username', res.username);
    },
    error: (err) => {
      console.log('❌ refresh échoué', err);
      this.clearSession();
      this._isReady.set(true);
    }
  });
}

  waitForReady(): Promise<void> {
    // Si déjà prêt → resolve immédiatement
    if (this._isReady()) {
      return Promise.resolve();
    }
    // Sinon → attend le prochain changement
    return new Promise(resolve => {
      toObservable(this._isReady)
        .pipe(filter(r => r), take(1))
        .subscribe(() => resolve());
    });
  }

  // ─────────────────────────────────────────────────────
  //  Méthodes HTTP → retournent des Observables
  //  + mettent à jour les signals en interne via tap()
  // ─────────────────────────────────────────────────────

  register(req: RegisterRequest): Observable<RegisterResponse> {
    // Pas de session après le register → l'user doit se connecter
    return this.authApi.register(req);
  }

  login(req: LoginRequest): Observable<AuthResponse> {
    return this.authApi.login(req).pipe(
      tap(res => {
        this.tokenStore.set(res.accessToken);
        this._username.set(res.username);
        this._isAuthenticated.set(true);
        localStorage.setItem('username', res.username);
      })
    );
  }

  // Appelé par l'interceptor en cas de 401
  refreshToken(): Observable<AuthResponse> {
    return this.authApi.refresh().pipe(
      tap(res => {
        this.tokenStore.set(res.accessToken);
        this._username.set(res.username);
        this._isAuthenticated.set(true);
        localStorage.setItem('username', res.username);
      })
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

  // Appelé par l'interceptor quand le refresh échoue
  logoutAndRedirect(reason: string = 'session_expired'): void {
    this.clearSession();
    this.router.navigate(['/login'], { queryParams: { reason } });
  }

  // ─────────────────────────────────────────────────────
  //  OAuth2 Google
  // ─────────────────────────────────────────────────────

  initiateGoogleLogin(): void {
    // Redirige le navigateur vers Spring qui démarre le flow Google
    window.location.href = `${this.getApiBaseUrl()}/oauth2/authorization/google`;
  }

  handleOAuth2Callback(code: string): Observable<AuthResponse> {
    return this.authApi.exchangeOAuth2Code(code).pipe(
      tap(res => {
        this.tokenStore.set(res.accessToken);
        this._username.set(res.username);
        this._isAuthenticated.set(true);
        localStorage.setItem('username', res.username);
      })
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
    const roles = this.jwtDecoder.decode(token)?.roles;
    if (!roles || roles.length === 0) return null;
    return roles[0].replace('ROLE_', '');
  }

  clearSession(): void {
    this.tokenStore.clear();
    localStorage.removeItem('username');
    this._isAuthenticated.set(false);
    this._username.set(null);
  }

  private getApiBaseUrl(): string {
    // Lazy import pour éviter une dépendance circulaire
    return (window as any).__apiUrl ?? 'http://localhost:8080';
  }
}
