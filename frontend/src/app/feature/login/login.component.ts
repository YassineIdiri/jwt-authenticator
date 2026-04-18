import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import {
  FormBuilder,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';
import { AuthService } from '../../service/auth.service';
import { ApiError, LoginRequest } from '../../models/auth.models';

@Component({
  selector: 'app-login',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './login.component.html',
})
export class LoginComponent {
  private fb     = inject(FormBuilder);
  private auth   = inject(AuthService);
  private router = inject(Router);
  private route  = inject(ActivatedRoute);

  // ── State local en signals ────────────────────────────────
  loading      = signal(false);
  serverError  = signal<string | null>(null);
  showPassword = signal(false);

  // ── Raison de redirection (session expirée, unauthorized…) ──
  // toSignal() : Observable → signal, parfait pour les queryParams
  reason = toSignal(
    this.route.queryParamMap.pipe(map(p => p.get('reason'))),
    { initialValue: null }
  );

  // ── Computed : message selon la raison ───────────────────
  reasonMessage = computed(() => {
    const map: Record<string, string> = {
      session_expired: 'Votre session a expiré. Veuillez vous reconnecter.',
      unauthorized:    'Vous devez être connecté pour accéder à cette page.',
    };
    return map[this.reason() ?? ''] ?? null;
  });

  // ── Formulaire ────────────────────────────────────────────
  form = this.fb.group({
    username:   ['', [Validators.required]],
    password:   ['', [Validators.required]],
    rememberMe: [false],
  });

  toggleShowPassword(): void {
    this.showPassword.update(v => !v);
  }

  // ── Helpers validation ────────────────────────────────────
  isInvalid(field: string): boolean {
    const ctrl = this.form.get(field)!;
    return ctrl.invalid && (ctrl.dirty || ctrl.touched);
  }

  hasError(field: string, error: string): boolean {
    const ctrl = this.form.get(field)!;
    return ctrl.hasError(error) && (ctrl.dirty || ctrl.touched);
  }

  // ── Submit ────────────────────────────────────────────────
  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    this.loading.set(true);
    this.serverError.set(null);

    const payload: LoginRequest = {
      username:   this.form.value.username!,
      password:   this.form.value.password!,
      rememberMe: this.form.value.rememberMe ?? false,
    };

    this.auth.login(payload).subscribe({
      next: () => this.router.navigate(['/home']),
      error: (err) => {
        this.loading.set(false);
        const apiError = err?.error as ApiError;
        this.serverError.set(this.mapError(apiError?.code));
      },
    });
  }

  // ── OAuth2 Google ─────────────────────────────────────────
  loginWithGoogle(): void {
    this.auth.initiateGoogleLogin();
  }

  // ── Mapping erreurs backend → messages FR ─────────────────
  private mapError(code: string): string {
    const map: Record<string, string> = {
      INVALID_CREDENTIALS:               'Identifiant ou mot de passe incorrect.',
      ACCOUNT_LOCKED:                    'Votre compte est temporairement bloqué.',
      ACCOUNT_DISABLED:                  'Votre compte a été désactivé.',
      OAUTH2_ACCOUNT_USE_GOOGLE_LOGIN:   'Ce compte utilise Google. Connectez-vous via Google.',
    };
    return map[code] ?? 'Une erreur est survenue. Veuillez réessayer.';
  }
}
