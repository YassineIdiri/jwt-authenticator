import {
  ChangeDetectionStrategy,
  Component,
  inject,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../service/auth.service';

@Component({
  selector: 'app-homepage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, RouterLink],
  templateUrl: './homepage.component.html',
})
export class HomepageComponent {
  private auth = inject(AuthService);

  isLoggedIn = this.auth.isAuthenticated;
  username   = this.auth.username;
}
