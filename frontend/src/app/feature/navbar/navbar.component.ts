import {
  ChangeDetectionStrategy,
  Component,
  inject,
  signal,
} from '@angular/core';
import { RouterLink, RouterLinkActive, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../service/auth.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, RouterLink, RouterLinkActive],
  templateUrl: './navbar.component.html',
})
export class NavbarComponent {
  private auth   = inject(AuthService);
  private router = inject(Router);

  // ── State ────────────────────────────────────────────────
  menuOpen = signal(false);

  // ── Signals depuis AuthService ────────────────────────────
  isLoggedIn    = this.auth.isAuthenticated;
  username      = this.auth.username;
  isAdmin       = this.auth.isAdmin;

  // ── Cart count (branché sur CartService plus tard) ────────
  cartCount = signal(0);

  // ── Actions ──────────────────────────────────────────────
  toggleMenu(): void {
    this.menuOpen.update(v => !v);
  }

  closeMenu(): void {
    this.menuOpen.set(false);
  }

  onLogout(): void {
    this.closeMenu();
    this.auth.logout().subscribe({
      next: () => this.router.navigate(['/login']),
    });
  }
}
