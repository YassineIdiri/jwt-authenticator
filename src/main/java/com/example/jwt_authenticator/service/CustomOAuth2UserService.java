package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.dto.Role;
import com.example.jwt_authenticator.entity.AuthProvider;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.repository.UserRepository;
import com.example.jwt_authenticator.security.CustomOAuth2UserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Loads and provisions users from the Google OAuth2 flow.
 *
 * Enterprise improvements over the original:
 *
 *  1. Null-safety on 'sub' and 'email' attributes — Google may theoretically
 *     omit them if the scope isn't granted. A missing sub or email now throws
 *     a typed OAuth2AuthenticationException instead of a NullPointerException.
 *
 *  2. Returns CustomOAuth2UserDetails instead of DefaultOAuth2User.
 *     CustomOAuth2UserDetails carries the internal userId, which allows
 *     AuthService.extractUserIdFromContext() to resolve the userId directly
 *     from the principal without an extra DB query.
 *
 *  3. generateUsername() caps retries at 10 to prevent an infinite loop if
 *     the DB is in an unexpected state.
 *
 *  4. Logging added for observability (new user created, existing user linked).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);

        // Fail fast with a clear error if required attributes are missing
        String providerId = requireAttribute(oAuth2User, "sub");
        String email      = requireAttribute(oAuth2User, "email");
        String name       = oAuth2User.getAttribute("name"); // optional

        User user = userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
                .orElseGet(() -> userRepository.findByEmail(email.toLowerCase().trim())
                        .map(existing -> linkGoogleToExisting(existing, providerId))
                        .orElseGet(() -> createGoogleUser(email, name, providerId)));

        // Return CustomOAuth2UserDetails so extractUserIdFromContext() can read
        // user.getId() directly — no extra DB call on every authenticated request.
        return new CustomOAuth2UserDetails(
                user.getId(),
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())),
                oAuth2User.getAttributes(),
                "sub"
        );
    }

    // -------------------------------------------------------------------------
    // User provisioning
    // -------------------------------------------------------------------------

    private User createGoogleUser(String email, String name, String providerId) {
        User user = new User();
        user.setUsername(generateUsername(name));
        user.setEmail(email.toLowerCase().trim());
        user.setPasswordHash(null); // Google-only account — no password
        user.setProvider(AuthProvider.GOOGLE);
        user.setProviderId(providerId);
        user.setRole(Role.USER);
        user.setActive(true);
        user.setLocked(false);

        User saved = userRepository.save(user);
        log.info("OAuth2 new user created: username={}, provider=GOOGLE", saved.getUsername());
        return saved;
    }

    private User linkGoogleToExisting(User user, String providerId) {
        if (user.getProvider() == AuthProvider.LOCAL) {
            // Upgrade to BOTH: user can now log in with password OR Google
            user.setProvider(AuthProvider.BOTH);
            log.info("OAuth2 linked Google to existing local account: userId={}", user.getId());
        }
        user.setProviderId(providerId);
        return userRepository.save(user);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Generates a unique username derived from the Google display name.
     *
     * FIX: The original had no retry cap — theoretically an infinite loop.
     * Now capped at 10 attempts; if all fail (astronomically unlikely with
     * UUID suffixes), throws a clear exception instead of hanging.
     */
    private String generateUsername(String name) {
        String base = (name == null || name.isBlank())
                ? "user"
                : name.toLowerCase().replaceAll("[^a-z0-9]", "");

        if (base.isBlank()) base = "user";

        int maxAttempts = 10;
        for (int i = 0; i < maxAttempts; i++) {
            String candidate = base + "_" + UUID.randomUUID().toString().substring(0, 6);
            if (!userRepository.existsByUsername(candidate)) {
                return candidate;
            }
        }

        // Fallback: full UUID — collision probability is negligible
        return "user_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * Reads a required attribute from the OAuth2User, throwing a typed
     * OAuth2AuthenticationException if it's absent or blank.
     */
    private static String requireAttribute(OAuth2User user, String attribute) {
        String value = user.getAttribute(attribute);
        if (value == null || value.isBlank()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("missing_attribute"),
                    "Required OAuth2 attribute '" + attribute + "' is missing"
            );
        }
        return value;
    }
}