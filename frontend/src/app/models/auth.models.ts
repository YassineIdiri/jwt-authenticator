// ─────────────────────────────────────────────────────
//  JWT Payload
//  Reflects the claims emitted by JwtService.createToken()
// ─────────────────────────────────────────────────────

export interface JwtPayload {
  // Standard claims — all now emitted by the backend
  sub: string;       // username
  jti: string;       // unique token ID — used for blacklisting on logout
  iss: string;       // issuer  (app.jwt.issuer)
  aud: string[];     // audience (app.jwt.audience) — JJWT serialises as array
  iat: number;       // issued at  (epoch seconds)
  exp: number;       // expires at (epoch seconds)

  // Custom claims
  roles: string[];   // e.g. ['ROLE_USER'] or ['ROLE_ADMIN']
}

// ─────────────────────────────────────────────────────
//  Auth API request / response models
// ─────────────────────────────────────────────────────

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface RegisterResponse {
  username:  string;
  email:     string;
  createdAt: string;
  message:   string;
}

export interface LoginRequest {
  username:   string;
  password:   string;
  rememberMe: boolean;
}

export interface AuthResponse {
  accessToken: string;
  expiresIn:   number;   // seconds until access token expiry
  username:    string;
}

export interface OAuth2ExchangeRequest {
  code: string;
}

export interface SessionResponse {
  id:         number;
  deviceName: string;
  ipAddress:  string;
  lastUsedAt: string;
  current:    boolean;
}

// ─────────────────────────────────────────────────────
//  Error response shape from the backend
//
//  Two shapes coexist depending on the source:
//
//  JwtAuthenticationFailureHandler (401 on JWT errors):
//    { timestamp, status, errorCode, message, path }
//
//  Global @ControllerAdvice (validation, business errors):
//    { timestamp, status, error, errorCode, message, path, traceId, details }
//
//  All fields beyond timestamp/status/message/path are optional
//  so this single type covers both shapes.
// ─────────────────────────────────────────────────────

export interface ApiError {
  timestamp: string;
  status:    number;
  message:   string;
  path:      string;

  // Single field for machine-readable error codes — used by both
  // JwtAuthenticationFailureHandler and GlobalExceptionHandler
  errorCode?: string;

  // Global handler additions
  error?:    string;   // HTTP status name — e.g. "CONFLICT", "UNAUTHORIZED"
  traceId?:  string;
  details?: {
    errors?: Record<string, string>;  // field-level validation errors
  };
}
