import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from '../service/auth.service';
import { firstValueFrom } from 'rxjs';

/**
 * Shared auth check used by authGuard and adminGuard.
 *
 * Waits for initAuth() to complete, then:
 *  1. If already logged in → allow
 *  2. If not → attempt a silent refresh (covers the case where
 *     the token expired while the guard was waiting)
 *  3. If refresh fails → redirect to login
 */
async function ensureAuth(auth: AuthService, router: Router): Promise<boolean> {
  await auth.waitForReady();

  if (auth.isLoggedIn()) return true;

  try {
    await firstValueFrom(auth.refreshToken());
    return true;
  } catch {
    router.navigate(['/login']);
    return false;
  }
}

/**
 * Protects any authenticated route.
 * Redirects to /login if the user has no valid session.
 */
export const authGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);
  return ensureAuth(auth, router);
};

/**
 * Protects admin-only routes.
 * Redirects to /login if not authenticated, to /home if authenticated but not ADMIN.
 */
export const adminGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);

  const ok = await ensureAuth(auth, router);
  if (!ok) return false;

  if (auth.isAdmin()) return true;

  router.navigate(['/home']);
  return false;
};

/**
 * Protects guest-only routes (login, register).
 * Redirects authenticated users to /home.
 *
 * Note: does NOT attempt a refresh — if the user is not currently
 * logged in memory, they stay on the guest page. This avoids the
 * awkward UX of silently logging someone in when they navigate to /login.
 */
export const guestGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);

  await auth.waitForReady();

  if (!auth.isLoggedIn()) return true;

  router.navigate(['/home']);
  return false;
};
