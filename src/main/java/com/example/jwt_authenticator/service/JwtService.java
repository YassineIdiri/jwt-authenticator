package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.config.properties.JwtProperties;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.exception.TokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.Function;

/**
 * JWT generation and validation service.
 *
 * Enterprise improvements over the original:
 *
 *  1. Secret decoded from Base64 (Decoders.BASE64) instead of raw UTF-8 bytes.
 *     Guarantees key material quality regardless of character encoding and
 *     integrates cleanly with secret managers (Vault, AWS Secrets Manager).
 *
 *  2. Standard JWT claims added:
 *       jti (JWT ID)  — UUID per token, required for blacklisting on logout
 *       iss (issuer)  — identifies this service, prevents token reuse across services
 *       aud (audience) — identifies the intended API, prevents token reuse across APIs
 *
 *  3. validateTokenStrict no longer re-parses the token to check expiry.
 *     parseAllClaims already throws ExpiredJwtException before the method body
 *     runs, so the manual Date comparison was dead code and a double parse.
 *
 *  4. ZoneOffset.UTC replaces ZoneId.systemDefault(). Container timezone is
 *     unreliable; UTC is always consistent.
 *
 *  5. extractJti() added — necessary for blacklisting access tokens on logout.
 */
@Slf4j
@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;
    private final String issuer;
    private final String audience;

    public JwtService(JwtProperties props) {
        this.signingKey   = buildSigningKey(props.secret());
        this.expirationMs = props.expiration();
        this.issuer       = props.issuer();
        this.audience     = props.audience();
    }

    // -------------------------------------------------------------------------
    // Token generation
    // -------------------------------------------------------------------------

    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(extraClaims);
        // Roles in claims: avoids a UserDetailsService call on every authorized endpoint
        claims.putIfAbsent("roles", toRoleNames(userDetails.getAuthorities()));
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Instant now = Instant.now();
        Instant exp = now.plusMillis(expirationMs);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuer(issuer)
                .audience().add(audience).and()
                // jti: unique token ID — store this in Redis on logout to blacklist the token
                // without waiting for natural expiry
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /**
     * Validates the token strictly — throws a typed exception on any failure.
     *
     * Note: expiry is already checked inside parseAllClaims (via the JJWT parser).
     * There is no need for a manual Date comparison; that would cause a second
     * token parse and would never be reached anyway because parseAllClaims
     * already threw before we got here.
     */
    public boolean validateTokenStrict(String token, UserDetails userDetails) {
        // parseAllClaims handles: expiry, signature, malformed, unsupported, issuer, audience
        String username = extractUsername(token);

        if (!username.equals(userDetails.getUsername())) {
            throw new InvalidTokenException("Token subject does not match authenticated user",
                    ErrorCode.INVALID_SUBJECT);
        }

        return true;
    }

    public boolean validateTokenSoft(String token, UserDetails userDetails) {
        try {
            return validateTokenStrict(token, userDetails);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Claim extraction
    // -------------------------------------------------------------------------

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Optional<String> extractUsernameSafe(String token) {
        try {
            return Optional.ofNullable(extractUsername(token));
        } catch (RuntimeException e) {
            log.debug("JWT extractUsernameSafe failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    /**
     * Extracts the jti (JWT ID) claim.
     * Use this to store revoked token IDs in Redis on logout.
     */
    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public long getTimeUntilExpirationSeconds(String token) {
        try {
            Date exp = extractExpiration(token);
            long diffMs = exp.getTime() - System.currentTimeMillis();
            return Math.max(0, diffMs / 1000);
        } catch (RuntimeException e) {
            return 0;
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        try {
            return resolver.apply(parseAllClaims(token));

        } catch (ExpiredJwtException e) {
            LocalDateTime expiredAt = toUtc(e.getClaims().getExpiration());
            throw new TokenExpiredException("Token has expired", expiredAt);

        } catch (SignatureException e) {
            throw new InvalidTokenException("Invalid token signature", ErrorCode.INVALID_SIGNATURE);

        } catch (MalformedJwtException e) {
            throw new InvalidTokenException("Token is malformed", ErrorCode.MALFORMED_TOKEN);

        } catch (UnsupportedJwtException e) {
            throw new InvalidTokenException("Token type is not supported", ErrorCode.UNSUPPORTED_TOKEN);

        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Token is empty or null", ErrorCode.INVALID_TOKEN);

        } catch (Exception e) {
            throw new InvalidTokenException("Token validation failed", ErrorCode.INVALID_TOKEN);
        }
    }

    private Claims parseAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                // Validates iss claim automatically — rejects tokens from other services
                .requireIssuer(issuer)
                // Validates aud claim automatically — rejects tokens intended for other APIs
                .requireAudience(audience)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Decodes the Base64-encoded secret and builds an HMAC-SHA key.
     *
     * The secret in application.properties must be a Base64-encoded string
     * representing at least 32 bytes (256 bits) of random data. Generate with:
     *   openssl rand -base64 64
     *
     * Using Base64 (rather than raw UTF-8 bytes) ensures the key has full
     * entropy and integrates with secret managers that store base64-encoded values.
     */
    private static SecretKey buildSigningKey(String base64Secret) {
        byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /** Always UTC — never rely on JVM/container default timezone. */
    private static LocalDateTime toUtc(Date date) {
        return date.toInstant().atZone(ZoneOffset.UTC).toLocalDateTime();
    }

    private static List<String> toRoleNames(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}