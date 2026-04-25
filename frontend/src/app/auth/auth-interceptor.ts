import {
  HttpErrorResponse,
  HttpInterceptorFn,
  HttpRequest,
} from '@angular/common/http';
import { inject, Injector } from '@angular/core';
import {
  BehaviorSubject,
  catchError,
  filter,
  switchMap,
  take,
  throwError,
} from 'rxjs';
import { TokenStore }  from '../service/token-store.service';
import { AuthService } from '../service/auth.service';
import { environment } from '../../environments/environment';

// ─────────────────────────────────────────────────────
//  Public routes — requests to these paths are forwarded
//  as-is without a Bearer token and without 401 handling.
//
//  KEEP IN SYNC with:
//    backend: app.security.public-paths in application.properties
//    backend: PublicPathsProperties
//
//  Ideally this list would come from an environment config or
//  a shared API contract. For now it is maintained manually.
// ─────────────────────────────────────────────────────

const PUBLIC_PATHS = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/auth/logout',
  '/api/auth/logout-all',
  '/api/auth/oauth2/exchange',
  '/api/auth/oauth2/failure',
  '/oauth2/',
  '/login/oauth2/',
];

function isPublicRoute(url: string): boolean {
  return PUBLIC_PATHS.some(path => url.includes(path));
}

function withBearer(req: HttpRequest<unknown>, token: string): HttpRequest<unknown> {
  return req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
}

function hasBearer(req: HttpRequest<unknown>): boolean {
  const h = req.headers.get('Authorization');
  return !!h && h.startsWith('Bearer ');
}

// ─────────────────────────────────────────────────────
//  Refresh mutex
//
//  Module-level state: survives across requests in the same app session.
//  When a 401 is received:
//    - First request: sets refreshing = true, triggers /refresh
//    - Concurrent requests: wait on refreshedToken$ until refresh completes
//
//  This prevents multiple simultaneous /refresh calls (which would
//  fail because the backend rotates the token on the first call,
//  making subsequent calls invalid — token reuse attack detection).
// ─────────────────────────────────────────────────────

let refreshing = false;
const refreshedToken$ = new BehaviorSubject<string | null>(null);

// ─────────────────────────────────────────────────────
//  Interceptor
// ─────────────────────────────────────────────────────

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const tokenStore = inject(TokenStore);
  // Lazy inject via Injector to avoid circular dependency:
  // AuthService → HttpClient → authInterceptor → AuthService
  const injector = inject(Injector);

  // Public routes: skip auth entirely
  if (isPublicRoute(req.url)) {
    return next(req);
  }

  // Attach Bearer token if available
  const token   = tokenStore.get();
  const request = token ? withBearer(req, token) : req;

  return next(request).pipe(
    catchError((err: unknown) => {
      // Only handle HTTP 401 on requests that had a Bearer token
      if (!(err instanceof HttpErrorResponse)) return throwError(() => err);
      if (err.status !== 401)                  return throwError(() => err);
      if (!hasBearer(request))                 return throwError(() => err);

      const auth = injector.get(AuthService);

      if (!refreshing) {
        // ── First 401: this request triggers the refresh ──
        refreshing = true;
        refreshedToken$.next(null);

        return auth.refreshToken().pipe(
          switchMap((res) => {
            refreshing = false;
            refreshedToken$.next(res.accessToken);
            // Retry the original request with the new token
            return next(withBearer(req, res.accessToken));
          }),
          catchError((refreshErr) => {
            // Refresh failed: session is gone → force re-login
            refreshing = false;
            refreshedToken$.next(null);
            auth.logoutAndRedirect('session_expired');
            return throwError(() => refreshErr);
          }),
        );
      }

      // ── Concurrent 401s: wait for the ongoing refresh to complete ──
      return refreshedToken$.pipe(
        filter((t): t is string => t !== null),
        take(1),
        switchMap((newToken) => next(withBearer(req, newToken))),
      );
    }),
  );
};
