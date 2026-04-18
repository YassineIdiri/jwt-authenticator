import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from '../service/auth.service';
import { firstValueFrom } from 'rxjs';

// Helper partagé — tente un refresh si token expiré
async function ensureAuth(auth: AuthService, router: Router): Promise<boolean> {
  await auth.waitForReady();

  if (auth.isLoggedIn()) return true;

  // ← DIFFÉRENCE : au lieu de redirect direct, on tente un refresh
  try {
    await firstValueFrom(auth.refreshToken());
    return true;
  } catch {
    router.navigate(['/login']);
    return false;
  }
}

export const authGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);
  return ensureAuth(auth, router);
};

export const adminGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);

  const ok = await ensureAuth(auth, router);
  if (!ok) return false;

  if (auth.isAdmin()) return true;
  router.navigate(['/home']);
  return false;
};

export const guestGuard: CanActivateFn = async () => {
  const auth   = inject(AuthService);
  const router = inject(Router);

  await auth.waitForReady();

  // guestGuard = page login/register
  // si connecté → redirige, pas besoin de tenter un refresh
  if (!auth.isLoggedIn()) return true;
  router.navigate(['/home']);
  return false;
};
