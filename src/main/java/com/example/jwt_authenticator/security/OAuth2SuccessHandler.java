package com.example.jwt_authenticator.security;

import com.example.jwt_authenticator.config.properties.OAuth2Properties;
import com.example.jwt_authenticator.entity.OAuth2PendingToken;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.repository.OAuth2PendingTokenRepository;
import com.example.jwt_authenticator.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Handles successful OAuth2 authentication.
 *
 * Flow:
 *   1. Google redirects back with an auth code → Spring Security validates it
 *      and calls this handler with a fully authenticated principal.
 *   2. We generate a short-lived, one-time exchange code and store it in DB.
 *   3. We redirect the frontend to the callback URL with only the exchange code
 *      in the query string — never a JWT in the URL (URL bar, history, logs).
 *   4. The frontend POSTs the code to /api/auth/oauth2/exchange to get JWT tokens.
 *
 * Enterprise improvements over the original:
 *
 *  1. Open redirect protection — redirectUri is validated against an explicit
 *     whitelist (OAuth2Properties.allowedRedirectUris) before redirecting.
 *     Without this, an attacker who manipulates the redirect_uri parameter
 *     could redirect the user (and the exchange code) to a malicious domain.
 *
 *  2. @Value replaced by OAuth2Properties (@ConfigurationProperties) —
 *     validated at startup, type-safe, centralised.
 *
 *  3. TTL is configurable (app.oauth2.code-ttl-seconds) instead of hardcoded 30s.
 *
 *  4. Uses CustomOAuth2UserDetails.getUserId() to look up the user by ID
 *     instead of by email — avoids an extra DB call and is more robust
 *     (email could theoretically change between OAuth2 login and this handler).
 *
 *  5. Typed exception + logging for the user-not-found case.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository               userRepository;
    private final OAuth2PendingTokenRepository pendingTokenRepository;
    private final OAuth2Properties             oauth2Props;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        // CustomOAuth2UserDetails carries the userId — no DB query needed here
        CustomOAuth2UserDetails principal = (CustomOAuth2UserDetails) authentication.getPrincipal();

        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new InvalidTokenException(
                        "User not found after OAuth2 authentication",
                        ErrorCode.USER_NOT_FOUND
                ));

        // -------------------------------------------------------------------------
        // Open redirect protection
        //
        // WHY: Without this check, an attacker can craft a URL like:
        //   /oauth2/authorize?redirect_uri=https://evil.com/steal
        // and after Google auth, the user (and the exchange code) end up on evil.com.
        //
        // We validate the target URI against the explicit whitelist in
        // OAuth2Properties.allowedRedirectUris before redirecting.
        // -------------------------------------------------------------------------
        String targetUri = oauth2Props.redirectUri();

        if (!oauth2Props.isAllowedRedirectUri(targetUri)) {
            log.warn("OAuth2 redirect to non-whitelisted URI blocked: uri={}", targetUri);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "OAuth2 redirect URI is not allowed");
            return;
        }

        // Generate one-time exchange code — TTL from configuration
        String code = UUID.randomUUID().toString();
        pendingTokenRepository.save(
                OAuth2PendingToken.builder()
                        .code(code)
                        .userId(user.getId())
                        .expiresAt(LocalDateTime.now().plusSeconds(oauth2Props.codeTtlSeconds()))
                        .build()
        );

        log.info("OAuth2 success: userId={}, issuing exchange code, redirecting to frontend",
                user.getId());

        // Redirect with the exchange code only — NEVER include a JWT in the URL
        // (URLs appear in browser history, server logs, and Referer headers)
        String redirectUrl = UriComponentsBuilder.fromUriString(targetUri)
                .queryParam("code", code)
                .build()
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}