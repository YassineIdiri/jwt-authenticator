package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.config.properties.RefreshProperties;
import com.example.jwt_authenticator.dto.SessionResponse;
import com.example.jwt_authenticator.dto.TokenType;
import com.example.jwt_authenticator.entity.RefreshToken;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.repository.OAuth2PendingTokenRepository;
import com.example.jwt_authenticator.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Manages the full lifecycle of opaque refresh tokens.
 *
 * Enterprise improvements over the original:
 *
 *  1. Configuration via @ConfigurationProperties (RefreshProperties) instead of
 *     scattered @Value fields. All values validated at startup.
 *
 *  2. Double query in getActiveSessions fixed: was fetching the token list twice
 *     (once into an unused variable, once into the stream). Now a single query.
 *
 *  3. Race condition in enforceMaxSessions addressed: the active-session count
 *     query and the eviction are now inside the same @Transactional boundary
 *     using a pessimistic-write lock on the repository query.
 *     See RefreshTokenRepository.countActiveSessionsForUpdate().
 *
 *  4. HMAC-SHA256 replaces plain SHA-256 for token hashing.
 *     A pepper (per-application secret) prevents offline dictionary attacks on
 *     a compromised token_hash column, even though UUIDs have high entropy.
 *
 *  5. extractIp relies on ForwardedHeaderFilter (registered in SecurityConfig)
 *     instead of reading X-Forwarded-For manually. This makes IP extraction safe
 *     against header spoofing (only trusted proxy headers are forwarded).
 *
 *  6. OAuth2 cleanup scheduled every 5 minutes instead of every minute.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository       refreshTokenRepository;
    private final OAuth2PendingTokenRepository pendingTokenRepository;
    private final RefreshProperties            refreshProps;   // replaces @Value fields

    public record Issued(String rawToken, LocalDateTime expiresAt, TokenType type, Long userId) {}

    // -------------------------------------------------------------------------
    // Issue
    // -------------------------------------------------------------------------

    @Transactional
    public Issued issue(Long userId, boolean rememberMe, HttpServletRequest request) {
        TokenType type = rememberMe ? TokenType.REMEMBER_ME : TokenType.REFRESH;
        int days       = rememberMe ? refreshProps.rememberDays() : refreshProps.days();

        enforceMaxSessions(userId);

        // Two UUIDs concatenated: ~256 bits of entropy before hashing
        String raw  = UUID.randomUUID() + "." + UUID.randomUUID();
        String hash = hmac(raw);

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime exp = now.plusDays(days);

        RefreshToken entity = RefreshToken.builder()
                .tokenHash(hash)
                .userId(userId)
                .tokenType(type)
                .createdAt(now)
                .lastUsedAt(now)
                .expiresAt(exp)
                .revoked(false)
                .ipAddress(extractIp(request))
                .userAgent(extractUserAgent(request))
                .deviceName(extractDeviceName(request))
                .build();

        refreshTokenRepository.save(entity);
        return new Issued(raw, exp, type, userId);
    }

    // -------------------------------------------------------------------------
    // Validate
    // -------------------------------------------------------------------------

    @Transactional
    public RefreshToken validate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidTokenException("Invalid refresh token", ErrorCode.REFRESH_TOKEN_INVALID);
        }

        RefreshToken token = refreshTokenRepository.findByTokenHash(hmac(rawToken))
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token",
                        ErrorCode.REFRESH_TOKEN_INVALID));

        if (token.isRevoked()) {
            // ---------------------------------------------------------------
            // TOKEN REUSE ATTACK DETECTION
            //
            // A revoked token being presented means one of two things:
            //   1. An attacker stole the token and used it first (rotation
            //      revoked it), and now the legitimate user is trying to use
            //      their copy — which is now revoked.
            //   2. A replay attack on an old token.
            //
            // In both cases the correct response is to revoke ALL sessions
            // for this user immediately. This forces every device to re-login,
            // neutralising any token the attacker may have obtained via rotation.
            //
            // This implements the "refresh token family" security pattern.
            // ---------------------------------------------------------------
            log.warn("SECURITY ALERT: revoked refresh token reuse detected for userId={} — " +
                    "possible token theft, revoking all sessions", token.getUserId());

            refreshTokenRepository.revokeAllByUserId(token.getUserId());

            throw new InvalidTokenException(
                    "Security violation: refresh token reuse detected. All sessions have been revoked.",
                    ErrorCode.REFRESH_TOKEN_REVOKED
            );
        }
        if (token.isExpired()) {
            throw new InvalidTokenException("Refresh token has expired",
                    ErrorCode.REFRESH_TOKEN_EXPIRED);
        }

        token.markAsUsed();
        return refreshTokenRepository.save(token);
    }

    // -------------------------------------------------------------------------
    // Rotate
    // -------------------------------------------------------------------------

    @Transactional
    public Issued rotate(String rawToken, HttpServletRequest request) {
        RefreshToken old = validate(rawToken);

        if (!refreshProps.rotate()) {
            // Rotation disabled: return same token (stateless-ish mode)
            return new Issued(rawToken, old.getExpiresAt(), old.getTokenType(), old.getUserId());
        }

        old.revoke();
        refreshTokenRepository.save(old);

        boolean rememberMe = old.getTokenType() == TokenType.REMEMBER_ME;
        return issue(old.getUserId(), rememberMe, request);
    }

    // -------------------------------------------------------------------------
    // Sessions
    // -------------------------------------------------------------------------

    /**
     * Returns active sessions for a user.
     *
     * FIX: The original called findByUserIdAndRevokedFalse twice — once into
     * an unused variable (dead debug code), once into the stream. This version
     * calls it once and uses the result directly.
     */
    public List<SessionResponse> getActiveSessions(Long userId, String currentRawToken) {
        String currentHash = hmac(currentRawToken);

        return refreshTokenRepository
                .findByUserIdAndRevokedFalse(userId)
                .stream()
                .filter(rt -> !rt.isExpired())
                .map(rt -> new SessionResponse(
                        rt.getId(),
                        rt.getDeviceName(),
                        rt.getIpAddress(),
                        rt.getLastUsedAt(),
                        rt.getTokenHash().equals(currentHash)
                ))
                .toList();
    }

    public void revokeSession(Long sessionId, Long userId) {
        RefreshToken rt = refreshTokenRepository.findById(sessionId)
                .orElseThrow(() -> new InvalidTokenException("Session not found",
                        ErrorCode.REFRESH_TOKEN_INVALID));

        if (!rt.getUserId().equals(userId)) {
            // Authorization check: users can only revoke their own sessions
            throw new InvalidTokenException("Access denied", ErrorCode.REFRESH_TOKEN_INVALID);
        }

        rt.revoke();
        refreshTokenRepository.save(rt);
    }

    /**
     * Read-only userId lookup — no side effects.
     * Used by logoutAll() to get the userId without triggering markAsUsed().
     */
    public Long getUserIdFromToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidTokenException("Invalid refresh token", ErrorCode.REFRESH_TOKEN_INVALID);
        }
        return refreshTokenRepository.findByTokenHash(hmac(rawToken))
                .filter(t -> !t.isRevoked() && !t.isExpired())
                .map(RefreshToken::getUserId)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token",
                        ErrorCode.REFRESH_TOKEN_INVALID));
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return;
        refreshTokenRepository.findByTokenHash(hmac(rawToken)).ifPresent(t -> {
            t.revoke();
            refreshTokenRepository.save(t);
        });
    }

    @Transactional
    public void revokeAll(Long userId) {
        refreshTokenRepository.revokeAllByUserId(userId);
    }

    // -------------------------------------------------------------------------
    // Scheduled cleanup
    // -------------------------------------------------------------------------

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredRefreshTokens() {
        LocalDateTime threshold = LocalDateTime.now().minusDays(7);
        int deleted = refreshTokenRepository.deleteExpiredTokens(threshold);
        log.info("Cleanup refresh tokens: deleted={}, threshold={}", deleted, threshold);
    }

    /**
     * OAuth2 pending tokens cleanup.
     *
     * FIX: Was running every minute (0 * * * * *) — unnecessary for short-lived
     * pending tokens that expire within seconds. Every 5 minutes is sufficient.
     */
    @Scheduled(cron = "0 */5 * * * *")
    @Transactional
    public void cleanupExpiredOAuth2Codes() {
        int deleted = pendingTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        if (deleted > 0) {
            log.info("Cleanup OAuth2 pending tokens: deleted={}", deleted);
        }
    }

    // -------------------------------------------------------------------------
    // Max sessions enforcement
    // -------------------------------------------------------------------------

    /**
     * Evicts the oldest active session when the user is at the session limit.
     *
     * FIX — Race condition: The original read countActiveSessions (a plain SELECT)
     * and then conditionally wrote, allowing two concurrent requests to both pass
     * the count check and both create sessions, exceeding maxActiveSessions.
     *
     * Solution: Use a SELECT FOR UPDATE on the count query (pessimistic write lock)
     * so that concurrent issue() calls for the same userId are serialized at the
     * DB level. See RefreshTokenRepository.countActiveSessionsForUpdate().
     *
     * Required repository method:
     *
     *   @Lock(LockModeType.PESSIMISTIC_WRITE)
     *   @Query("SELECT COUNT(rt) FROM RefreshToken rt " +
     *          "WHERE rt.userId = :userId AND rt.revoked = false AND rt.expiresAt > :now")
     *   long countActiveSessionsForUpdate(@Param("userId") Long userId,
     *                                     @Param("now") LocalDateTime now);
     */
    private void enforceMaxSessions(Long userId) {
        LocalDateTime now    = LocalDateTime.now();
        // Pessimistic lock: serializes concurrent session creation for this userId
        long active = refreshTokenRepository.countActiveSessionsForUpdate(userId, now);

        if (active < refreshProps.maxActiveSessions()) return;

        // Evict oldest active session to make room for the new one
        refreshTokenRepository
                .findValidTokensByUserId(userId, now)
                .stream()
                .min((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()))
                .ifPresent(oldest -> {
                    oldest.revoke();
                    refreshTokenRepository.save(oldest);
                    log.info("Max sessions reached for userId={}: evicted sessionId={}",
                            userId, oldest.getId());
                });
    }

    // -------------------------------------------------------------------------
    // Hashing
    // -------------------------------------------------------------------------

    /**
     * HMAC-SHA256 with a per-application pepper.
     *
     * Why HMAC over plain SHA-256:
     *   Even though two UUIDs give ~256 bits of entropy (making rainbow tables
     *   impractical), a compromised DB + knowledge of the token format could
     *   enable offline brute-force. The pepper (kept in a secret manager, not the DB)
     *   makes offline attacks impossible without the key.
     *
     * The pepper comes from app.security.refresh.token-pepper (env var REFRESH_TOKEN_PEPPER).
     */
    private String hmac(String raw) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    refreshProps.tokenPepper().getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            ));
            return HexFormat.of().formatHex(mac.doFinal(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    // -------------------------------------------------------------------------
    // Request metadata extraction
    // -------------------------------------------------------------------------

    /**
     * IP extraction is now trivial because ForwardedHeaderFilter (registered in
     * SecurityConfig) pre-processes X-Forwarded-For and rewrites request.getRemoteAddr()
     * with the real client IP. This removes the need to manually read proxy headers
     * here, which was spoofable by any client that injected a fake X-Forwarded-For.
     */
    private String extractIp(HttpServletRequest request) {
        return request != null ? request.getRemoteAddr() : null;
    }

    private String extractUserAgent(HttpServletRequest request) {
        if (request == null) return null;
        String ua = request.getHeader("User-Agent");
        // Truncate to match column length (user_agent VARCHAR 500)
        return (ua != null && ua.length() > 500) ? ua.substring(0, 500) : ua;
    }

    private String extractDeviceName(HttpServletRequest request) {
        if (request == null) return "Unknown";
        String ua = request.getHeader("User-Agent");
        if (ua == null) return "Unknown";
        if (ua.contains("iPhone") || ua.contains("iPad")) return "iOS Device";
        if (ua.contains("Android"))   return "Android Device";
        if (ua.contains("Firefox"))   return "Firefox";
        if (ua.contains("Chrome"))    return "Chrome";
        if (ua.contains("Windows"))   return "Windows PC";
        if (ua.contains("Macintosh")) return "Mac";
        if (ua.contains("Linux"))     return "Linux PC";
        return "Unknown Device";
    }
}