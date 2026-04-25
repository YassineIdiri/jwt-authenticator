import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import {
  LoginRequest,
  RegisterRequest,
  AuthResponse,
  RegisterResponse,
  SessionResponse
} from '../models/auth.models';  // ✅ import centralisé

@Injectable({ providedIn: 'root' })
export class AuthApiService {

  private http = inject(HttpClient);
  private readonly api = `${environment.apiUrl}/api/auth`;

  register(req: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.api}/register`, req);
  }

  login(req: LoginRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.api}/login`, req, {
      withCredentials: true
    });
  }

  refresh(): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.api}/refresh`, {}, {
      withCredentials: true
    });
  }

  logout(): Observable<void> {
    return this.http.post<void>(`${this.api}/logout`, {}, {
      withCredentials: true
    });
  }

  logoutAll(): Observable<void> {
    return this.http.post<void>(`${this.api}/logout-all`, {}, {
      withCredentials: true
    });
  }

  exchangeOAuth2Code(code: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.api}/oauth2/exchange`, { code }, {
      withCredentials: true
    });
  }

  getSessions(): Observable<SessionResponse[]> {
    return this.http.get<SessionResponse[]>(`${this.api}/sessions`, {
      withCredentials: true
    });
  }

  revokeSession(id: number): Observable<void> {
    return this.http.delete<void>(`${this.api}/sessions/${id}`, {
      withCredentials: true
    });
  }

  revokeOtherSessions(): Observable<void> {
    return this.http.delete<void>(`${this.api}/sessions/others`, {
      withCredentials: true
    });
  }
}
