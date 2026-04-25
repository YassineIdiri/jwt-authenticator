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

  loading      = signal(false);
  serverError  = signal<string | null>(null);
  showPassword = signal(false);

  reason = toSignal(
    this.route.queryParamMap.pipe(map(p => p.get('reason'))),
    { initialValue: null }
  );

  reasonMessage = computed(() => {
    const messages: Record<string, string> = {
      session_expired: 'Votre session a expiré. Veuillez vous reconnecter.',
      unauthorized:    'Vous devez être connecté pour accéder à cette page.',
    };
    return messages[this.reason() ?? ''] ?? null;
  });

  form = this.fb.group({
    username:   ['', [Validators.required]],
    password:   ['', [Validators.required]],
    rememberMe: [false],
  });

  toggleShowPassword(): void {
    this.showPassword.update(v => !v);
  }

  isInvalid(field: string): boolean {
    const ctrl = this.form.get(field)!;
    return ctrl.invalid && (ctrl.dirty || ctrl.touched);
  }

  hasError(field: string, error: string): boolean {
    const ctrl = this.form.get(field)!;
    return ctrl.hasError(error) && (ctrl.dirty || ctrl.touched);
  }

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
        // FIX: code → errorCode (unified field name across all backend error responses)
        this.serverError.set(this.mapError(apiError?.errorCode));
      },
    });
  }

  loginWithGoogle(): void {
    this.auth.initiateGoogleLogin();
  }

  private mapError(errorCode: string | undefined): string {
    const messages: Record<string, string> = {
      INVALID_CREDENTIALS:             'Identifiant ou mot de passe incorrect.',
      ACCOUNT_LOCKED:                  'Votre compte est temporairement bloqué.',
      ACCOUNT_DISABLED:                'Votre compte a été désactivé.',
      OAUTH2_ACCOUNT_USE_GOOGLE_LOGIN: 'Ce compte utilise Google. Connectez-vous via Google.',
    };
    return messages[errorCode ?? ''] ?? 'Une erreur est survenue. Veuillez réessayer.';
  }
}
