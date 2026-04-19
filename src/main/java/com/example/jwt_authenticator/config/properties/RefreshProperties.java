package com.example.jwt_authenticator.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Refresh token + cookie configuration properties.
 *
 * Replaces scattered @Value injections in RefreshTokenService.
 * All values are validated at startup via the compact constructor.
 *
 * Required additions to application.properties:
 *
 *   # Refresh tokens
 *   app.security.refresh.days=7
 *   app.security.refresh.remember-days=30
 *   app.security.refresh.rotate=true
 *   app.security.refresh.max-active-sessions=5
 *   app.security.refresh.token-pepper=${REFRESH_TOKEN_PEPPER}   # HMAC pepper (required)
 *
 *   # Refresh cookie
 *   app.security.refresh.cookie-name=refresh_token
 *   app.security.refresh.cookie-path=/api/auth
 *   app.security.refresh.secure=true                            # always true in prod
 *   app.security.refresh.same-site=Lax
 */
@ConfigurationProperties("app.security.refresh")
public record RefreshProperties(
        int days,
        int rememberDays,
        boolean rotate,
        int maxActiveSessions,

        // Cookie settings
        String cookieName,
        String cookiePath,
        boolean secure,
        String sameSite,

        // HMAC pepper for token hashing — prevents rainbow-table attacks on leaked DB
        String tokenPepper
) {
    public RefreshProperties {
        if (days <= 0)
            throw new IllegalStateException("app.security.refresh.days must be positive");
        if (rememberDays <= 0)
            throw new IllegalStateException("app.security.refresh.remember-days must be positive");
        if (maxActiveSessions <= 0)
            throw new IllegalStateException("app.security.refresh.max-active-sessions must be positive");
        if (cookieName == null || cookieName.isBlank())
            throw new IllegalStateException("app.security.refresh.cookie-name must be configured");
        if (tokenPepper == null || tokenPepper.isBlank())
            throw new IllegalStateException("app.security.refresh.token-pepper must be configured (set via env var REFRESH_TOKEN_PEPPER)");
    }
}