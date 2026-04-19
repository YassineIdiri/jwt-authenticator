package com.example.jwt_authenticator.security;

import com.example.jwt_authenticator.config.properties.PublicPathsProperties;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.exception.TokenExpiredException;
import com.example.jwt_authenticator.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT authentication filter — executed once per request.
 *
 * Enterprise improvements over the original:
 *  1. No @Lazy: replaced AuthenticationEntryPoint with JwtAuthenticationFailureHandler,
 *     which is a standalone @Component with no dependency on SecurityConfig.
 *  2. shouldNotFilter reads from PublicPathsProperties — single source of truth
 *     shared with SecurityConfig. No more duplicated whitelist.
 *  3. Duplicate catch blocks merged into one via multi-catch.
 *  4. Token blacklist check hook — plug in a Redis-backed TokenBlacklistService
 *     to invalidate access tokens on logout without waiting for natural expiry.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFailureHandler failureHandler;  // no SecurityConfig dependency
    private final PublicPathsProperties publicPaths;               // shared whitelist

    // -------------------------------------------------------------------------
    // Whitelist — delegates to PublicPathsProperties so there is only ONE place
    // to add/remove public paths (application.properties → PublicPathsProperties).
    // -------------------------------------------------------------------------

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return publicPaths.matches(request.getServletPath());
    }

    // -------------------------------------------------------------------------
    // Core filter logic
    // -------------------------------------------------------------------------

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        // Already authenticated upstream (e.g. OAuth2 session)
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        String token = resolveBearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));

        // No token → pass through; endpoint security is enforced by the authorization rules.
        // Unauthenticated access to protected endpoints will trigger the EntryPoint.
        if (token == null) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String username = jwtService.extractUsername(token);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // validateTokenStrict throws typed exceptions — no silent swallowing
            jwtService.validateTokenStrict(token, userDetails);

            // ----------------------------------------------------------------
            // TOKEN BLACKLIST HOOK
            // Uncomment and inject TokenBlacklistService to invalidate tokens
            // on logout without waiting for natural JWT expiry.
            //
            // if (tokenBlacklistService.isRevoked(jwtService.extractJti(token))) {
            //     failureHandler.handle(request, response, ErrorCode.INVALID_TOKEN, "Token has been revoked");
            //     return;
            // }
            // ----------------------------------------------------------------

            var auth = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);

            chain.doFilter(request, response);

        } catch (TokenExpiredException | InvalidTokenException e) {
            // Typed exceptions: delegate error code to the failure handler
            failureHandler.handle(request, response, e.getErrorCode(), e.getMessage());

        } catch (Exception e) {
            // Unexpected exceptions (e.g. UserDetailsService DB failure)
            // — generic error, no internal detail exposed to client
            log.error("Unexpected error during JWT authentication on {} {}",
                    request.getMethod(), request.getServletPath(), e);
            failureHandler.handle(request, response, ErrorCode.INVALID_TOKEN, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the raw JWT from the Authorization header.
     * Returns null if the header is absent, malformed, or the token is blank.
     */
    private String resolveBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) return null;
        if (!authorizationHeader.startsWith("Bearer ")) return null;
        String token = authorizationHeader.substring(7).trim();
        return token.isEmpty() ? null : token;
    }
}