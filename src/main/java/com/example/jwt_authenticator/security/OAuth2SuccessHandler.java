package com.example.jwt_authenticator.security;

import com.example.jwt_authenticator.entity.OAuth2PendingToken;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.repository.OAuth2PendingTokenRepository;
import com.example.jwt_authenticator.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final OAuth2PendingTokenRepository pendingTokenRepository;

    @Value("${app.oauth2.redirect-uri:http://localhost:4200/oauth2/callback}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("User not found after OAuth2"));

        // Générer un code temporaire (usage unique, TTL 30 secondes)
        String code = UUID.randomUUID().toString();
        pendingTokenRepository.save(
                OAuth2PendingToken.builder()
                        .code(code)
                        .userId(user.getId())
                        .expiresAt(LocalDateTime.now().plusSeconds(30))
                        .build()
        );

        // Rediriger avec le code uniquement — jamais le JWT dans l'URL
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("code", code)
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}