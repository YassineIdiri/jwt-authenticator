import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { NavbarComponent } from '../../feature/navbar/navbar.component';

@Component({
  selector: 'app-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, NavbarComponent],
  template: `
    <div class="min-h-screen flex flex-col bg-[#0e0e0e]">
      <app-navbar />
      <main class="flex-1 pt-16">
        <router-outlet />
      </main>
    </div>
  `,
})
export class LayoutComponent {}
