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
    console.log('🟡 ngOnInit');
    this.auth.waitForReady().then(() => {
      console.log('🟢 waitForReady resolved');
      this.loadSessions();
    });
  }

  loadSessions(): void {
    console.log('📡 loadSessions appelé');
    this.loading.set(true);
    this.error.set(null);

    this.authApi.getSessions().subscribe({
      next: (data) => {
        console.log('✅ sessions reçues', data);
        this.sessions.set(data);
        this.loading.set(false);
      },
      error: (err) => {
        console.log('❌ erreur sessions', err);
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
    this.auth.logoutAll().subscribe({
      next: () => this.loadSessions()
    });
  }

  onLogout(): void {
    this.auth.logout().subscribe();
  }

  formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    return new Intl.DateTimeFormat('fr-FR', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    }).format(date);
  }
}
