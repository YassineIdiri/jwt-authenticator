import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import {
  AbstractControl,
  FormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../service/auth.service';
import { ApiError, RegisterRequest } from '../../models/auth.models';

// ── Validator : les deux mots de passe doivent correspondre ──
function matchPasswords(group: AbstractControl): ValidationErrors | null {
  const pw  = group.get('password')?.value;
  const cpw = group.get('confirmPassword')?.value;
  return pw === cpw ? null : { passwordMismatch: true };
}

// ── Validator : force du mot de passe ────────────────────────
function passwordStrength(ctrl: AbstractControl): ValidationErrors | null {
  const v = ctrl.value as string;
  if (!v) return null;
  const ok =
    /[A-Z]/.test(v) &&
    /[a-z]/.test(v) &&
    /[0-9]/.test(v) &&
    /[@$!%*?&]/.test(v);
  return ok ? null : { weakPassword: true };
}

@Component({
  selector: 'app-register',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './register.component.html',
})
export class RegisterComponent {
  private fb     = inject(FormBuilder);
  private auth   = inject(AuthService);
  private router = inject(Router);

  // ── State local en signals ────────────────────────────────
  loading       = signal(false);
  serverError   = signal<string | null>(null);
  success       = signal(false);
  showPassword  = signal(false);
  showConfirm   = signal(false);

  // ── Formulaire ────────────────────────────────────────────
  form = this.fb.group(
    {
      username:        ['', [Validators.required, Validators.minLength(3), Validators.maxLength(30)]],
      email:           ['', [Validators.required, Validators.email]],
      password:        ['', [Validators.required, Validators.minLength(8), passwordStrength]],
      confirmPassword: ['', Validators.required],
    },
    { validators: matchPasswords }
  );

  // ── Computed : force du mot de passe (1 faible → 4 fort) ──
  passwordStrengthLevel = computed(() => {
    const v = this.form.get('password')?.value ?? '';
    if (!v || v.length < 8) return 0;
    let score = 0;
    if (/[a-z]/.test(v)) score++;
    if (/[A-Z]/.test(v)) score++;
    if (/[0-9]/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    return score;
  });

  passwordStrengthLabel = computed(() => {
    const labels = ['', 'Faible', 'Moyen', 'Bien', 'Fort'];
    return labels[this.passwordStrengthLevel()] ?? '';
  });

  passwordStrengthColor = computed(() => {
    const colors = ['', 'bg-red-500', 'bg-orange-400', 'bg-yellow-400', 'bg-emerald-500'];
    return colors[this.passwordStrengthLevel()] ?? '';
  });

  // ── Toggle visibilité mots de passe ──────────────────────
  // ✅ Méthodes explicites — les arrow functions (v => !v)
  //    ne sont pas supportées dans les templates Angular
  toggleShowPassword(): void {
    this.showPassword.update(v => !v);
  }

  toggleShowConfirm(): void {
    this.showConfirm.update(v => !v);
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

  get passwordMismatch(): boolean {
    return (
      this.form.hasError('passwordMismatch') &&
      (this.form.get('confirmPassword')?.dirty || this.form.get('confirmPassword')?.touched) === true
    );
  }

  // ── Submit ────────────────────────────────────────────────
  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    this.loading.set(true);
    this.serverError.set(null);

    const { username, email, password } = this.form.value;

    // ✅ confirmPassword volontairement exclu de la requête
    const payload: RegisterRequest = {
      username: username!,
      email:    email!,
      password: password!,
    };

    this.auth.register(payload).subscribe({
      next: () => {
        this.loading.set(false);
        this.success.set(true);
        setTimeout(() => this.router.navigate(['/login']), 2000);
      },
      error: (err) => {
        this.loading.set(false);
        const apiError = err?.error as ApiError;
        this.serverError.set(this.mapError(apiError?.code));
      },
    });
  }

  // ── OAuth2 Google ──────────────────────────────────────────
  loginWithGoogle(): void {
    this.auth.initiateGoogleLogin();
  }

  // ── Mapping erreurs backend → messages FR ─────────────────
  private mapError(code: string): string {
    const map: Record<string, string> = {
      USER_ALREADY_EXISTS:  'Cet identifiant est déjà utilisé.',
      EMAIL_ALREADY_EXISTS: 'Cette adresse e-mail est déjà associée à un compte.',
    };
    return map[code] ?? 'Une erreur est survenue. Veuillez réessayer.';
  }
}
