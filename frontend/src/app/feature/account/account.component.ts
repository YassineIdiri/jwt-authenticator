import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../service/auth.service';
import { AuthApiService } from '../../service/auth-api.service';
import { SessionResponse } from '../../models/auth.models';
import { Router } from '@angular/router';

type Tab = 'sessions' | 'profile';

@Component({
  selector: 'app-account',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule],
  templateUrl: './account.component.html',
})
export class AccountComponent implements OnInit {
  private auth    = inject(AuthService);
  private authApi = inject(AuthApiService);
  private router = inject(Router);

  username = this.auth.username;
  isAdmin  = this.auth.isAdmin;

  activeTab = signal<Tab>('sessions');
  sessions  = signal<SessionResponse[]>([]);
  loading   = signal(false);
  error     = signal<string | null>(null);

  currentSession = computed(() =>
    this.sessions().find(s => s.current) ?? null
  );

  otherSessions = computed(() =>
    this.sessions().filter(s => !s.current)
  );

  ngOnInit(): void {
    this.auth.waitForReady().then(() => this.loadSessions());
  }

  loadSessions(): void {
    this.loading.set(true);
    this.error.set(null);

    this.authApi.getSessions().subscribe({
      next: (data) => {
        this.sessions.set(data);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Impossible de charger les sessions.');
        this.loading.set(false);
      }
    });
  }

  setTab(tab: Tab): void {
    this.activeTab.set(tab);
  }

  revokeSession(id: number): void {
    this.authApi.revokeSession(id).subscribe({
      next: () => this.loadSessions(),
      error: () => this.error.set('Erreur lors de la déconnexion.')
    });
  }

  revokeAllOthers(): void {
    this.loading.set(true);
    this.error.set(null);

    this.authApi.revokeOtherSessions().subscribe({
      next: () => this.loadSessions(),
      error: () => {
        this.error.set('Erreur lors de la déconnexion des autres appareils.');
        this.loading.set(false);
      }
    });
  }

  onLogout(): void {
    this.auth.logout().subscribe({
      next: () => this.router.navigate(['/login'])
    });
  }
  formatDate(dateStr: string): string {
      const date = new Date(dateStr);
      return new Intl.DateTimeFormat('fr-FR', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
      }).format(date);
    }
  }


