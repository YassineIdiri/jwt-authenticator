package com.example.jwt_authenticator.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

/**
 * Extension of DefaultOAuth2User that carries the internal database userId.
 *
 * Why this exists:
 *   DefaultOAuth2User only exposes Google attributes (sub, email, name...).
 *   To get the internal userId from the SecurityContext after OAuth2 login,
 *   the original code had to do an extra DB query by email on every request:
 *
 *     userRepository.findByEmail(oauth.getAttribute("email")).getId()
 *
 *   With CustomOAuth2UserDetails, the userId is stored directly in the principal
 *   at login time (in CustomOAuth2UserService) and is available instantly:
 *
 *     ((CustomOAuth2UserDetails) principal).getUserId()
 *
 *   This eliminates the N+1 DB query on every OAuth2-authenticated request.
 */
public class CustomOAuth2UserDetails extends DefaultOAuth2User {

    private final Long userId;

    public CustomOAuth2UserDetails(
            Long userId,
            Collection<? extends GrantedAuthority> authorities,
            Map<String, Object> attributes,
            String nameAttributeKey
    ) {
        super(authorities, attributes, nameAttributeKey);
        this.userId = userId;
    }

    public Long getUserId() {
        return userId;
    }
}