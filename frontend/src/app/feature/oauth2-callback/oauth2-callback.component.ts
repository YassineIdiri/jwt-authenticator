import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { AuthService } from '../../service/auth.service';
import { ApiError } from '../../models/auth.models';

@Component({
  selector: 'app-oauth2-callback',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule],
  templateUrl: './oauth2-callback.component.html',
})
export class OAuth2CallbackComponent implements OnInit {
  private route  = inject(ActivatedRoute);
  private router = inject(Router);
  private auth   = inject(AuthService);

  error = signal<string | null>(null);

  ngOnInit(): void {
    const code       = this.route.snapshot.queryParamMap.get('code');
    const errorParam = this.route.snapshot.queryParamMap.get('error');

    if (errorParam) {
      this.error.set('Connexion Google refusée. Veuillez réessayer.');
      return;
    }

    if (!code) {
      this.error.set('Code de connexion manquant.');
      return;
    }

    this.auth.handleOAuth2Callback(code).subscribe({
      next: () => this.router.navigate(['/']),
      error: (err: HttpErrorResponse) => {
        const apiError = err?.error as ApiError;
        // FIX: code → errorCode (unified field name)
        this.error.set(
          apiError?.errorCode === 'OAUTH2_CODE_EXPIRED'
            ? 'Le lien de connexion a expiré. Veuillez réessayer.'
            : 'Échec de la connexion Google. Veuillez réessayer.'
        );
      },
    });
  }
}
