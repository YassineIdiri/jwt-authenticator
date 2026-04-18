import { Injectable } from '@angular/core';

/**
 * Stocke l'access token en mémoire uniquement.
 * - Plus sécurisé que localStorage contre les attaques XSS
 * - Disparaît à la fermeture de l'onglet (normal : le refresh cookie prend le relais)
 */
@Injectable({ providedIn: 'root' })
export class TokenStore {

  private token: string | null = null;

  get(): string | null {
    return this.token;
  }

  set(token: string): void {
    this.token = token;
  }

  clear(): void {
    this.token = null;
  }

  has(): boolean {
    return this.token !== null;
  }
}
