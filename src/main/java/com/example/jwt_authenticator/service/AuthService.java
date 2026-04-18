package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.dto.*;
import com.example.jwt_authenticator.entity.OAuth2PendingToken;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.exception.UserAlreadyExistsException;
import com.example.jwt_authenticator.repository.OAuth2PendingTokenRepository;
import com.example.jwt_authenticator.repository.UserRepository;
import com.example.jwt_authenticator.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2PendingTokenRepository pendingTokenRepository;

    public record AuthResult(String accessToken, long expiresIn, String username,
                             String refreshTokenRaw, java.time.LocalDateTime refreshExpiresAt) {}

    private static final Pattern COMMON_PASSWORDS = Pattern.compile(
            ".*(password|123456|qwerty|admin|letmein|welcome).*",
            Pattern.CASE_INSENSITIVE
    );

    @Transactional
    public AuthResult exchangeOAuth2Code(String code, HttpServletRequest httpReq) {
        OAuth2PendingToken pending = pendingTokenRepository.findByCode(code)
                .orElseThrow(() -> new BadCredentialsException("INVALID_OAUTH2_CODE"));

        // Suppression immédiate — usage unique
        pendingTokenRepository.delete(pending);

        if (pending.isExpired()) {
            throw new BadCredentialsException("OAUTH2_CODE_EXPIRED");
        }

        User user = userRepository.findById(pending.getUserId())
                .orElseThrow(() -> new BadCredentialsException("USER_NOT_FOUND"));

        assertAccountOk(user);

        String accessToken = issueAccessToken(user);
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);

        var issued = refreshTokenService.issue(user.getId(), false, httpReq);

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                issued.rawToken(), issued.expiresAt());
    }

    @Transactional
    public RegisterResponse register(RegisterRequest req) {

        if (COMMON_PASSWORDS.matcher(req.password()).matches()) {
            throw new IllegalArgumentException("This password is too common and easily guessable");
        }

        if (userRepository.existsByUsername(req.username())) {
            throw new UserAlreadyExistsException("USER_ALREADY_EXISTS");
        }

        if (userRepository.existsByEmail(req.email())) {
            throw new UserAlreadyExistsException("EMAIL_ALREADY_EXISTS");
        }

        String normalizedEmail = req.email().toLowerCase().trim();

        String hashedPassword = passwordEncoder.encode(req.password());

        User user = new User();
        user.setUsername(req.username().trim());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(hashedPassword);
        user.setRole(Role.USER);
        user.setActive(true);
        user.setLocked(false);
        user.setCreatedAt(LocalDateTime.now());
        User savedUser = userRepository.save(user);

        return RegisterResponse.of(
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.getCreatedAt()
        );
    }


    public AuthResult login(LoginRequest req, HttpServletRequest httpReq) {
        User user = userRepository.findByUsername(req.username())
                .orElseThrow(() -> new BadCredentialsException("INVALID_CREDENTIALS"));

        // ✅ Avant : bloquait si provider != LOCAL
        // ✅ Maintenant : on bloque seulement si le compte est GOOGLE pur (pas de password)
        if (!user.supportsPasswordLogin()) {
            throw new BadCredentialsException("OAUTH2_ACCOUNT_USE_GOOGLE_LOGIN");
        }

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("INVALID_CREDENTIALS");
        }

        assertAccountOk(user);

        String accessToken = issueAccessToken(user);
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);

        var issued = refreshTokenService.issue(user.getId(), req.rememberMe(), httpReq);

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                issued.rawToken(), issued.expiresAt());
    }

    public AuthResult refresh(String refreshTokenRaw, HttpServletRequest httpReq) {
        var rotated = refreshTokenService.rotate(refreshTokenRaw, httpReq);

        User user = userRepository.findById(rotated.userId())
                .orElseThrow(() -> new BadCredentialsException("USER_NOT_FOUND"));

        assertAccountOk(user);

        String accessToken = issueAccessToken(user);
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                rotated.rawToken(), rotated.expiresAt());
    }

    public void logout(String refreshTokenRaw) {
        refreshTokenService.revoke(refreshTokenRaw);
    }

    public void logoutAll(String refreshTokenRaw) {
        Long userId = refreshTokenService.validate(refreshTokenRaw).getUserId();
        refreshTokenService.revokeAll(userId);
    }

    public Long extractUserIdFromContext() {
        var principal = SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();

        log.info("Principal type: {}", principal.getClass().getSimpleName()); // ← ajoute ça

        if (principal instanceof CustomUserDetails u) {
            return u.getUserId();
        }

        if (principal instanceof OAuth2User oauth) {
            String email = oauth.getAttribute("email");
            return userRepository.findByEmail(email)
                    .orElseThrow(() -> new BadCredentialsException("USER_NOT_FOUND"))
                    .getId();
        }

        throw new BadCredentialsException("UNKNOWN_PRINCIPAL");
    }

    public static AuthResponse toResponse(AuthResult r) {
        return AuthResponse.of(r.accessToken(), r.expiresIn(), r.username());
    }

    private void assertAccountOk(User user) {
        if (user.isLocked()) throw new BadCredentialsException("ACCOUNT_LOCKED");
        if (!user.isActive()) throw new BadCredentialsException("ACCOUNT_DISABLED");
    }

    private String issueAccessToken(User user) {
        var principal = new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPasswordHash(),
                user.isActive(),
                user.isLocked(),
                user.getRole()
        );
        return jwtService.generateToken(principal);
    }
}
