package com.example.jwt_authenticator.security;

import com.example.jwt_authenticator.config.properties.RefreshProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;

/**
 * Factory for the refresh token HttpOnly cookie.
 *
 * Centralises all cookie creation, deletion, and extraction in one place
 * so the controller never constructs ResponseCookie manually.
 *
 * Enterprise improvements over the original:
 *
 *  1. @Value fields replaced by RefreshProperties — single source of truth,
 *     validated at startup, no scattered property key strings.
 *
 *  2. maxAge calculated via Instant instead of LocalDateTime.
 *     LocalDateTime has no timezone — if the JVM timezone shifts (DST, Docker
 *     restart) between token issuance and cookie creation, the duration is wrong.
 *     Instant is always UTC and unambiguous.
 *
 *  3. cookieName() proxy method removed — callers that need the cookie name
 *     should inject RefreshProperties directly.
 */
@Component
@RequiredArgsConstructor
public class RefreshCookieFactory {

    private final RefreshProperties refreshProps;

    /**
     * Creates a Set-Cookie header value for a new or rotated refresh token.
     *
     * @param rawToken  the raw (unhashed) refresh token to store in the cookie
     * @param expiresAt when the refresh token expires (used to compute Max-Age)
     */
    public ResponseCookie create(String rawToken, LocalDateTime expiresAt) {
        // Convert to Instant (UTC) before computing duration — avoids LocalDateTime timezone ambiguity
        Instant expInstant = expiresAt.toInstant(ZoneOffset.UTC);
        long maxAgeSeconds = Math.max(0, Duration.between(Instant.now(), expInstant).getSeconds());

        return ResponseCookie.from(refreshProps.cookieName(), rawToken)
                .httpOnly(true)                       // not accessible via JavaScript — XSS protection
                .secure(refreshProps.secure())        // HTTPS only (set true in prod)
                .sameSite(refreshProps.sameSite())    // Lax: sent on top-level navigations, not cross-site AJAX
                .path(refreshProps.cookiePath())      // scoped to /api/auth — not sent on every request
                .maxAge(maxAgeSeconds)
                .build();
    }

    /**
     * Creates a cookie that immediately expires, effectively deleting it from the browser.
     * Used on logout.
     */
    public ResponseCookie delete() {
        return ResponseCookie.from(refreshProps.cookieName(), "")
                .httpOnly(true)
                .secure(refreshProps.secure())
                .sameSite(refreshProps.sameSite())
                .path(refreshProps.cookiePath())
                .maxAge(0)
                .build();
    }

    /**
     * Extracts the raw refresh token from the incoming request cookies.
     * Returns null if the cookie is absent.
     */
    public String readFrom(HttpServletRequest request) {
        if (request == null || request.getCookies() == null) return null;

        return Arrays.stream(request.getCookies())
                .filter(c -> refreshProps.cookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}