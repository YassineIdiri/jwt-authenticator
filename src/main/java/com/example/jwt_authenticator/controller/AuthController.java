package com.example.jwt_authenticator.controller;

import com.example.jwt_authenticator.dto.*;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.security.RefreshCookieFactory;
import com.example.jwt_authenticator.service.AuthService;
import com.example.jwt_authenticator.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Authentication REST controller.
 *
 * Enterprise improvements over the original:
 *
 *  1. @Valid added on login() — LoginRequest fields (username, password) are
 *     now validated before reaching the service layer.
 *
 *  2. Explicit null guard on refresh token from cookie — returns a clean 401
 *     instead of a NullPointerException propagating through the service stack.
 *
 *  3. "Set-Cookie" string literal replaced by HttpHeaders.SET_COOKIE constant
 *     — avoids silent typos that would cause the cookie to never be set.
 *
 *  4. /oauth2/failure endpoint added — was referenced in SecurityConfig's
 *     failureHandler redirect but didn't exist, causing a 404.
 *
 *  5. getSessions() null-safe on currentToken — if the user has no cookie
 *     (e.g. pure OAuth2 session), getActiveSessions receives an empty string
 *     instead of null, avoiding an NPE inside hmac().
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService          authService;
    private final RefreshCookieFactory refreshCookieFactory;
    private final RefreshTokenService  refreshTokenService;

    // -------------------------------------------------------------------------
    // Register
    // -------------------------------------------------------------------------

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        RegisterResponse response = authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    /**
     * FIX: @Valid was missing — username/password constraints on LoginRequest
     * (e.g. @NotBlank) were never enforced before reaching AuthService.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest httpReq
    ) {
        var result = authService.login(req, httpReq);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        refreshCookieFactory.create(result.refreshTokenRaw(), result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    // -------------------------------------------------------------------------
    // Refresh
    // -------------------------------------------------------------------------

    /**
     * FIX: readFrom() returns null if the cookie is absent.
     * The original passed null straight to authService.refresh(), which
     * propagated it through the service stack before producing an unclear error.
     * Now we guard explicitly and return a clean 401.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest httpReq) {
        String refreshToken = requireRefreshCookie(httpReq);

        var result = authService.refresh(refreshToken, httpReq);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        refreshCookieFactory.create(result.refreshTokenRaw(), result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    // -------------------------------------------------------------------------
    // Logout
    // -------------------------------------------------------------------------

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest httpReq) {
        // readFrom() may return null if cookie was already cleared — that's fine,
        // RefreshTokenService.revoke(null) is a no-op.
        String refreshToken = refreshCookieFactory.readFrom(httpReq);
        authService.logout(refreshToken);

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, refreshCookieFactory.delete().toString())
                .build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest httpReq) {
        String refreshToken = requireRefreshCookie(httpReq);
        authService.logoutAll(refreshToken);

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, refreshCookieFactory.delete().toString())
                .build();
    }

    // -------------------------------------------------------------------------
    // OAuth2 exchange
    // -------------------------------------------------------------------------

    @PostMapping("/oauth2/exchange")
    public ResponseEntity<AuthResponse> exchangeOAuth2Code(
            @Valid @RequestBody OAuth2ExchangeRequest req,
            HttpServletRequest httpReq
    ) {
        var result = authService.exchangeOAuth2Code(req.code(), httpReq);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        refreshCookieFactory.create(result.refreshTokenRaw(), result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    /**
     * OAuth2 failure landing endpoint.
     *
     * FIX: This route was referenced in SecurityConfig's OAuth2 failureHandler:
     *   res.sendRedirect("/api/auth/oauth2/failure?error=...")
     * but was never declared, causing a 404 after every failed OAuth2 attempt.
     *
     * Returns a JSON body so the frontend can display a meaningful error.
     * The error parameter is a generic code (e.g. "oauth2_authentication_failed")
     * — never an internal exception message.
     */
    @GetMapping("/oauth2/failure")
    public ResponseEntity<Map<String, String>> oauth2Failure(
            @RequestParam(defaultValue = "oauth2_authentication_failed") String error
    ) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                        "errorCode", "OAUTH2_FAILURE",
                        "message",   "OAuth2 authentication failed",
                        "detail",    error
                ));
    }

    // -------------------------------------------------------------------------
    // Sessions
    // -------------------------------------------------------------------------

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getSessions(HttpServletRequest httpReq) {
        Long userId = authService.extractUserIdFromContext();

        // FIX: readFrom() may return null for pure OAuth2 sessions (no refresh cookie yet).
        // getActiveSessions() calls hmac() on the token — passing null would NPE.
        // Empty string produces a hash that will never match any stored token,
        // so no session will be marked as "current" — which is the correct behaviour.
        String currentToken = refreshCookieFactory.readFrom(httpReq);
        String safeToken    = currentToken != null ? currentToken : "";

        return ResponseEntity.ok(refreshTokenService.getActiveSessions(userId, safeToken));
    }

    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<Void> revokeSession(@PathVariable Long id) {
        refreshTokenService.revokeSession(id, authService.extractUserIdFromContext());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/sessions/others")
    public ResponseEntity<Void> revokeOtherSessions(HttpServletRequest httpReq) {
        String refreshToken = requireRefreshCookie(httpReq);
        Long userId = authService.extractUserIdFromContext();
        refreshTokenService.revokeAllOthers(refreshToken, userId);

        return ResponseEntity.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Reads the refresh token cookie and throws a typed 401 if it's absent.
     * Used on endpoints where a missing cookie is always an error
     * (refresh, logout-all) — as opposed to logout where null is a no-op.
     */
    private String requireRefreshCookie(HttpServletRequest request) {
        String token = refreshCookieFactory.readFrom(request);
        if (token == null || token.isBlank()) {
            throw new InvalidTokenException("Refresh token cookie is missing",
                    ErrorCode.REFRESH_TOKEN_INVALID);
        }
        return token;
    }
}