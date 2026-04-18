package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.dto.Role;
import com.example.jwt_authenticator.entity.AuthProvider;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);

        String providerId = oAuth2User.getAttribute("sub");
        String email      = oAuth2User.getAttribute("email");
        String name       = oAuth2User.getAttribute("name");

        User user = userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
                .orElseGet(() -> userRepository.findByEmail(email)
                        .map(existing -> linkGoogleToExisting(existing, providerId))
                        .orElseGet(() -> createGoogleUser(email, name, providerId)));

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())),
                oAuth2User.getAttributes(),
                "sub"
        );
    }

    private User createGoogleUser(String email, String name, String providerId) {
        User user = new User();
        user.setUsername(generateUsername(name));
        user.setEmail(email.toLowerCase().trim());
        user.setPasswordHash(null);
        user.setProvider(AuthProvider.GOOGLE);
        user.setProviderId(providerId);
        user.setRole(Role.USER);
        user.setActive(true);
        user.setLocked(false);
        return userRepository.save(user);
    }

    private User linkGoogleToExisting(User user, String providerId) {
        if (user.getProvider() == AuthProvider.LOCAL) {
            user.setProvider(AuthProvider.BOTH);  // reste connecté par password aussi
        }
        user.setProviderId(providerId);
        return userRepository.save(user);
    }

    private String generateUsername(String name) {
        String base = name == null ? "user"
                : name.toLowerCase().replaceAll("[^a-z0-9]", "");
        if (base.isBlank()) base = "user";

        // Suffix aléatoire pour éviter les collisions
        String candidate;
        do {
            candidate = base + "_" + UUID.randomUUID().toString().substring(0, 6);
        } while (userRepository.existsByUsername(candidate));

        return candidate;
    }
}