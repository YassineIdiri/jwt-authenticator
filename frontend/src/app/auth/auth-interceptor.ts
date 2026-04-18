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
import { TokenStore } from '../service/token-store.service';
import { AuthService } from '../service/auth.service';

let refreshing = false;
const refreshedToken$ = new BehaviorSubject<string | null>(null);

function isPublicRoute(url: string): boolean {
  const publicPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/refresh',
    '/api/auth/logout',
    '/api/auth/logout-all',
    '/api/auth/oauth2/exchange',
    '/oauth2/',
    '/login/oauth2/'
  ];
  return publicPaths.some(path => url.includes(path));
}

function hasBearer(req: HttpRequest<unknown>): boolean {
  const h = req.headers.get('Authorization');
  return !!h && h.startsWith('Bearer ');
}

function withBearer(req: HttpRequest<unknown>, token: string): HttpRequest<unknown> {
  return req.clone({
    setHeaders: { Authorization: `Bearer ${token}` },
  });
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const tokenStore = inject(TokenStore);
  const injector   = inject(Injector); // ← Injector, pas AuthService

  if (isPublicRoute(req.url)) {
    return next(req);
  }

  const token   = tokenStore.get();
  const request = token ? withBearer(req, token) : req;

  return next(request).pipe(
    catchError((err: unknown) => {
      if (!(err instanceof HttpErrorResponse)) return throwError(() => err);
      if (err.status !== 401)                  return throwError(() => err);
      if (!hasBearer(request))                 return throwError(() => err);

      if (!refreshing) {
        refreshing = true;
        refreshedToken$.next(null);

        const auth = injector.get(AuthService); // ← lazy, résout la boucle

        return auth.refreshToken().pipe(
          switchMap((res) => {
            refreshing = false;
            refreshedToken$.next(res.accessToken);
            return next(withBearer(req, res.accessToken));
          }),
          catchError((refreshErr) => {
            refreshing = false;
            injector.get(AuthService).logoutAndRedirect('session_expired');
            return throwError(() => refreshErr);
          }),
        );
      }

      return refreshedToken$.pipe(
        filter((t): t is string => t !== null),
        take(1),
        switchMap((newToken) => next(withBearer(req, newToken))),
      );
    }),
  );
};
