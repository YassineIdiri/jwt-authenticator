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
import { toSignal } from '@angular/core/rxjs-interop';
import { AuthService } from '../../service/auth.service';
import { ApiError, RegisterRequest } from '../../models/auth.models';

function matchPasswords(group: AbstractControl): ValidationErrors | null {
  const pw  = group.get('password')?.value;
  const cpw = group.get('confirmPassword')?.value;
  return pw === cpw ? null : { passwordMismatch: true };
}

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

  loading       = signal(false);
  serverError   = signal<string | null>(null);
  success       = signal(false);
  showPassword  = signal(false);
  showConfirm   = signal(false);

  form = this.fb.group(
    {
      username:        ['', [Validators.required, Validators.minLength(3), Validators.maxLength(30)]],
      email:           ['', [Validators.required, Validators.email]],
      password:        ['', [Validators.required, Validators.minLength(10), passwordStrength]],
      confirmPassword: ['', Validators.required],
    },
    { validators: matchPasswords }
  );

  // ─────────────────────────────────────────────────────
  //  FIX: computed() ne réagit pas aux valeurs d'un FormGroup
  //  car form.get('password')?.value n'est pas un signal Angular.
  //
  //  toSignal(valueChanges) convertit l'Observable des changements
  //  en signal réactif — les computed se mettent à jour
  //  automatiquement à chaque frappe dans le champ.
  // ─────────────────────────────────────────────────────

  passwordValue = toSignal(
    this.form.get('password')!.valueChanges,
    { initialValue: '' }
  );

  passwordStrengthLevel = computed(() => {
    const v = this.passwordValue() ?? '';
    if (!v || v.length < 10) return 0;
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

  toggleShowPassword(): void { this.showPassword.update(v => !v); }
  toggleShowConfirm():  void { this.showConfirm.update(v => !v);  }

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

  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    this.loading.set(true);
    this.serverError.set(null);

    const { username, email, password } = this.form.value;

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
        this.serverError.set(this.mapError(apiError?.errorCode));
      },
    });
  }

  loginWithGoogle(): void {
    this.auth.initiateGoogleLogin();
  }

  private mapError(errorCode: string | undefined): string {
    const messages: Record<string, string> = {
      USER_ALREADY_EXISTS:  'Cet identifiant est déjà utilisé.',
      EMAIL_ALREADY_EXISTS: 'Cette adresse e-mail est déjà associée à un compte.',
      VALIDATION_ERROR:     'Veuillez vérifier les informations saisies.',
    };
    return messages[errorCode ?? ''] ?? 'Une erreur est survenue. Veuillez réessayer.';
  }
}
