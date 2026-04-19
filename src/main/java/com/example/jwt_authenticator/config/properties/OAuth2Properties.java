package com.example.jwt_authenticator.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * OAuth2 configuration properties.
 *
 * Add to application.properties:
 *
 *   app.oauth2.redirect-uri=${APP_OAUTH2_REDIRECT_URI:http://localhost:4200/oauth2/callback}
 *
 *   # Whitelist of allowed redirect URIs — open redirect protection.
 *   # Any URI not in this list will be rejected by OAuth2SuccessHandler.
 *   app.oauth2.allowed-redirect-uris=\
 *     http://localhost:4200/oauth2/callback,\
 *     https://app.mydomain.com/oauth2/callback
 *
 *   # TTL in seconds for the one-time OAuth2 exchange code (default 30s)
 *   app.oauth2.code-ttl-seconds=30
 */
@ConfigurationProperties("app.oauth2")
public record OAuth2Properties(
        String redirectUri,
        List<String> allowedRedirectUris,
        int codeTtlSeconds
) {
    public OAuth2Properties {
        if (redirectUri == null || redirectUri.isBlank())
            throw new IllegalStateException("app.oauth2.redirect-uri must be configured");
        if (allowedRedirectUris == null || allowedRedirectUris.isEmpty())
            throw new IllegalStateException("app.oauth2.allowed-redirect-uris must contain at least one URI");
        if (codeTtlSeconds <= 0)
            throw new IllegalStateException("app.oauth2.code-ttl-seconds must be positive");

        allowedRedirectUris = List.copyOf(allowedRedirectUris);
    }

    /** Returns true if the given URI is in the whitelist. */
    public boolean isAllowedRedirectUri(String uri) {
        return uri != null && allowedRedirectUris.contains(uri);
    }
}