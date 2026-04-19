package com.example.jwt_authenticator.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT configuration properties.
 *
 * Required in application.properties / environment:
 *   app.jwt.secret   — Base64-encoded HMAC-SHA256 key (min 256 bits = 32 bytes before encoding)
 *   app.jwt.expiration — access token TTL in milliseconds
 *   app.jwt.issuer     — token issuer claim (iss), identifies this service
 *   app.jwt.audience   — token audience claim (aud), identifies the intended API
 *
 * Example:
 *   app.jwt.secret=${APP_JWT_SECRET}
 *   app.jwt.expiration=900000        # 15 minutes
 *   app.jwt.issuer=my-auth-service
 *   app.jwt.audience=my-api
 */
@ConfigurationProperties("app.jwt")
public record JwtProperties(
        String secret,
        long expiration,
        String issuer,
        String audience
) {
    /**
     * Fail fast at startup if required properties are missing or invalid.
     * Avoids a misconfigured secret only being discovered at runtime.
     */
    public JwtProperties {
        if (secret == null || secret.isBlank())
            throw new IllegalStateException("app.jwt.secret must be configured");
        if (expiration <= 0)
            throw new IllegalStateException("app.jwt.expiration must be a positive number of milliseconds");
        if (issuer == null || issuer.isBlank())
            throw new IllegalStateException("app.jwt.issuer must be configured");
        if (audience == null || audience.isBlank())
            throw new IllegalStateException("app.jwt.audience must be configured");
    }
}