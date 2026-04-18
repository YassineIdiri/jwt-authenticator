import { Routes } from '@angular/router';
import { authGuard, guestGuard, adminGuard } from './auth/auth.guard';
import { LoginComponent }         from './feature/login/login.component';
import { RegisterComponent }      from './feature/register/register.component';
import { OAuth2CallbackComponent } from './feature/oauth2-callback/oauth2-callback.component';
import { LayoutComponent }        from './shared/layout/layout.component';
import { HomepageComponent }      from './feature/homepage/homepage.component';
import { AccountComponent }       from './feature/account/account.component';

export const routes: Routes = [
  { path: 'login',           component: LoginComponent,         canActivate: [guestGuard] },
  { path: 'register',        component: RegisterComponent,      canActivate: [guestGuard] },
  { path: 'oauth2/callback', component: OAuth2CallbackComponent },
  {
    path: '',
    component: LayoutComponent,
    children: [
      { path: '',        component: HomepageComponent },
      { path: 'account', component: AccountComponent, canActivate: [authGuard] },
    ],
  },
  { path: '**', redirectTo: '' },
];
