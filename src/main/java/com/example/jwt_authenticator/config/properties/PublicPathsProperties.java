package com.example.jwt_authenticator.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Centralised whitelist of public (unauthenticated) paths.
 *
 * Both SecurityConfig (permitAll) and JwtAuthenticationFilter (shouldNotFilter)
 * read from this single source, eliminating the duplication that caused
 * maintenance drift between the two classes.
 *
 * Add to application.properties:
 *
 *   # Exact matches — no trailing wildcard
 *   app.security.public-paths.exact=\
 *     /api/auth/login,\
 *     /api/auth/register,\
 *     /api/auth/refresh,\
 *     /api/auth/logout,\
 *     /api/auth/logout-all,\
 *     /api/auth/oauth2/exchange,\
 *     /api/auth/oauth2/failure
 *
 *   # Prefix matches — anything starting with these paths
 *   app.security.public-paths.prefixes=\
 *     /oauth2/,\
 *     /login/oauth2/,\
 *     /swagger-ui,\
 *     /v3/api-docs
 */
@ConfigurationProperties("app.security.public-paths")
public record PublicPathsProperties(
        List<String> exact,
        List<String> prefixes
) {
    /**
     * Defensive copy + null-safety so Spring never injects a mutable list.
     */
    public PublicPathsProperties {
        exact    = exact    != null ? List.copyOf(exact)    : List.of();
        prefixes = prefixes != null ? List.copyOf(prefixes) : List.of();
    }

    /** True if the given path matches any exact entry or any prefix entry. */
    public boolean matches(String path) {
        if (path == null) return false;
        if (exact.contains(path)) return true;
        return prefixes.stream().anyMatch(path::startsWith);
    }
}