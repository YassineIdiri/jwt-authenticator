package com.example.jwt_authenticator.service;

import com.example.jwt_authenticator.dto.*;
import com.example.jwt_authenticator.entity.OAuth2PendingToken;
import com.example.jwt_authenticator.entity.User;
import com.example.jwt_authenticator.exception.ErrorCode;
import com.example.jwt_authenticator.exception.InvalidTokenException;
import com.example.jwt_authenticator.exception.UserAlreadyExistsException;
import com.example.jwt_authenticator.repository.OAuth2PendingTokenRepository;
import com.example.jwt_authenticator.repository.UserRepository;
import com.example.jwt_authenticator.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.passay.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.jwt_authenticator.security.CustomOAuth2UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Core authentication service.
 *
 * Enterprise improvements over the original:
 *
 *  1. login() delegates to AuthenticationManager instead of manually calling
 *     passwordEncoder.matches(). Spring Security handles events, listeners,
 *     and future mechanisms (MFA, lockout) automatically.
 *
 *  2. All throws use typed exceptions (InvalidTokenException, UserAlreadyExistsException)
 *     with ErrorCode enums — no more raw BadCredentialsException with string messages
 *     that could leak internal detail to the client.
 *
 *  3. Password policy enforced by Passay (length, upper, lower, digit, special char)
 *     instead of a 6-word regex. Add the passay dependency to pom.xml:
 *       <dependency>
 *           <groupId>org.passay</groupId>
 *           <artifactId>passay</artifactId>
 *           <version>1.6.4</version>
 *       </dependency>
 *
 *  4. issueAccessToken() loads UserDetails via UserDetailsService instead of
 *     constructing CustomUserDetails manually — robust to constructor changes.
 *
 *  5. logoutAll() no longer calls validate() (which had a DB write side-effect)
 *     just to get the userId. It uses a dedicated read-only lookup instead.
 *
 *  6. Debug log.info on principal type removed — was running on every authenticated request.
 *
 *  7. Email format validation belongs on the DTO (@Email Jakarta annotation).
 *     The service only normalises (lowercase + trim), trusting the DTO already validated.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository              userRepository;
    private final PasswordEncoder             passwordEncoder;
    private final JwtService                  jwtService;
    private final RefreshTokenService         refreshTokenService;
    private final OAuth2PendingTokenRepository pendingTokenRepository;
    private final AuthenticationManager       authenticationManager;
    private final UserDetailsService          userDetailsService;

    public record AuthResult(
            String accessToken,
            long expiresIn,
            String username,
            String refreshTokenRaw,
            LocalDateTime refreshExpiresAt
    ) {}

    // -------------------------------------------------------------------------
    // Password policy (Passay)
    // -------------------------------------------------------------------------

    /**
     * Enterprise password policy:
     *  - 10–128 characters
     *  - at least 1 uppercase letter
     *  - at least 1 lowercase letter
     *  - at least 1 digit
     *  - at least 1 special character
     *  - no whitespace
     *
     * Replaces the original 6-word regex which blocked "password" and "123456"
     * but accepted "aaaaaaaa" or "11111111" without complaint.
     *
     * To also check against HaveIBeenPwned (leaked passwords database),
     * inject a HibpPasswordValidator and call it here.
     */
    private static final PasswordValidator PASSWORD_VALIDATOR = new PasswordValidator(List.of(
            new LengthRule(10, 128),
            new CharacterRule(EnglishCharacterData.UpperCase, 1),
            new CharacterRule(EnglishCharacterData.LowerCase, 1),
            new CharacterRule(EnglishCharacterData.Digit, 1),
            new CharacterRule(EnglishCharacterData.Special, 1),
            new WhitespaceRule()
    ));

    // -------------------------------------------------------------------------
    // OAuth2 exchange
    // -------------------------------------------------------------------------

    @Transactional
    public AuthResult exchangeOAuth2Code(String code, HttpServletRequest httpReq) {
        OAuth2PendingToken pending = pendingTokenRepository.findByCode(code)
                .orElseThrow(() -> new InvalidTokenException(
                        "Invalid or unknown OAuth2 exchange code",
                        ErrorCode.INVALID_TOKEN
                ));

        // Delete immediately — single use code
        pendingTokenRepository.delete(pending);

        if (pending.isExpired()) {
            throw new InvalidTokenException("OAuth2 exchange code has expired", ErrorCode.TOKEN_EXPIRED);
        }

        User user = userRepository.findById(pending.getUserId())
                .orElseThrow(() -> new InvalidTokenException("User not found", ErrorCode.USER_NOT_FOUND));

        assertAccountOk(user);

        String accessToken = issueAccessToken(user.getUsername());
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);
        var issued = refreshTokenService.issue(user.getId(), false, httpReq);

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                issued.rawToken(), issued.expiresAt());
    }

    // -------------------------------------------------------------------------
    // Register
    // -------------------------------------------------------------------------

    @Transactional
    public RegisterResponse register(RegisterRequest req) {

        // Password policy — Passay throws with a human-readable violation list
        RuleResult result = PASSWORD_VALIDATOR.validate(new PasswordData(req.password()));
        if (!result.isValid()) {
            String violations = String.join(", ", PASSWORD_VALIDATOR.getMessages(result));
            throw new IllegalArgumentException("Password does not meet requirements: " + violations);
        }

        if (userRepository.existsByUsername(req.username())) {
            throw new UserAlreadyExistsException("Username is already taken");
        }

        if (userRepository.existsByEmail(req.email().toLowerCase().trim())) {
            throw new UserAlreadyExistsException("Email is already registered");
        }

        // Passwords must NOT be trimmed — a leading/trailing space is intentional user input
        String hashedPassword  = passwordEncoder.encode(req.password());
        String normalizedEmail = req.email().toLowerCase().trim();

        User user = new User();
        user.setUsername(req.username().trim());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(hashedPassword);
        user.setRole(Role.USER);
        user.setActive(true);
        user.setLocked(false);
        user.setCreatedAt(LocalDateTime.now());

        User saved = userRepository.save(user);
        log.info("New user registered: username={}", saved.getUsername());

        return RegisterResponse.of(saved.getUsername(), saved.getEmail(), saved.getCreatedAt());
    }

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    /**
     * Delegates credential verification to AuthenticationManager.
     *
     * Why this matters vs the original manual passwordEncoder.matches():
     *  - Spring Security fires AuthenticationSuccessEvent / AuthenticationFailureEvent
     *    automatically, which listeners can use for audit logging, brute-force
     *    tracking, or alerting without touching this class.
     *  - Future features (MFA, account lockout after N failures) plug in at the
     *    AuthenticationProvider level — this method needs no changes.
     *  - CustomUserDetailsService.loadUserByUsername() is called internally by
     *    Spring Security, which means LockedException / DisabledException are
     *    thrown from one consistent place (CustomUserDetailsService) rather than
     *    being duplicated here.
     */
    public AuthResult login(LoginRequest req, HttpServletRequest httpReq) {
        // authenticate() calls CustomUserDetailsService.loadUserByUsername() internally.
        // Throws AuthenticationException (BadCredentialsException, LockedException,
        // DisabledException) on failure — let these propagate to the global handler.
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username(), req.password())
        );

        CustomUserDetails principal = (CustomUserDetails) auth.getPrincipal();

        // supportsPasswordLogin() guards against Google-only accounts that have no password hash
        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new InvalidTokenException("User not found", ErrorCode.USER_NOT_FOUND));

        if (!user.supportsPasswordLogin()) {
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "This account uses Google login. Please sign in with Google."
            );
        }

        String accessToken = issueAccessToken(principal.getUsername());
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);
        var issued = refreshTokenService.issue(user.getId(), req.rememberMe(), httpReq);

        log.info("User logged in: username={}", user.getUsername());

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                issued.rawToken(), issued.expiresAt());
    }

    // -------------------------------------------------------------------------
    // Refresh
    // -------------------------------------------------------------------------

    public AuthResult refresh(String refreshTokenRaw, HttpServletRequest httpReq) {
        var rotated = refreshTokenService.rotate(refreshTokenRaw, httpReq);

        User user = userRepository.findById(rotated.userId())
                .orElseThrow(() -> new InvalidTokenException("User not found", ErrorCode.USER_NOT_FOUND));

        assertAccountOk(user);

        String accessToken = issueAccessToken(user.getUsername());
        long expiresIn = jwtService.getTimeUntilExpirationSeconds(accessToken);

        return new AuthResult(accessToken, expiresIn, user.getUsername(),
                rotated.rawToken(), rotated.expiresAt());
    }

    // -------------------------------------------------------------------------
    // Logout
    // -------------------------------------------------------------------------

    public void logout(String refreshTokenRaw) {
        refreshTokenService.revoke(refreshTokenRaw);
    }

    /**
     * Logs out all sessions for the user.
     *
     * FIX: The original called refreshTokenService.validate() just to get the userId.
     * validate() has a side-effect: it marks the token as "last used" and saves it to DB.
     * That's a pointless write since we're about to revoke everything anyway.
     *
     * Now we use a dedicated read-only hash lookup that has no side effects.
     */
    public void logoutAll(String refreshTokenRaw) {
        Long userId = refreshTokenService.getUserIdFromToken(refreshTokenRaw);
        refreshTokenService.revokeAll(userId);
    }

    // -------------------------------------------------------------------------
    // Principal resolution
    // -------------------------------------------------------------------------

    public Long extractUserIdFromContext() {
        Object principal = SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();

        if (principal instanceof CustomUserDetails u) {
            return u.getUserId();
        }

        // OAuth2 session (only present during the OAuth2 flow itself, before JWT is issued).
        // CustomOAuth2UserDetails carries the userId directly — no DB query needed.
        if (principal instanceof CustomOAuth2UserDetails oauth) {
            return oauth.getUserId();
        }

        throw new InvalidTokenException("Unknown principal type: "
                + principal.getClass().getSimpleName(), ErrorCode.INVALID_TOKEN);
    }

    // -------------------------------------------------------------------------
    // Response mapping
    // -------------------------------------------------------------------------

    public static AuthResponse toResponse(AuthResult r) {
        return AuthResponse.of(r.accessToken(), r.expiresIn(), r.username());
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Loads a fresh UserDetails from the DB via UserDetailsService.
     *
     * FIX: The original constructed CustomUserDetails manually from a User entity.
     * If CustomUserDetails' constructor signature changes, that call site silently
     * compiles but produces a wrong object. Delegating to UserDetailsService means
     * there is exactly ONE place that builds CustomUserDetails: CustomUserDetailsService.
     */
    private String issueAccessToken(String username) {
        var userDetails = userDetailsService.loadUserByUsername(username);
        return jwtService.generateToken(userDetails);
    }

    /**
     * Hard account status check.
     * Called on paths where Spring Security doesn't check status itself
     * (e.g. refresh, OAuth2 exchange) — i.e. when there's no authenticate() call.
     *
     * On the login path this is redundant (CustomUserDetailsService already throws
     * LockedException / DisabledException), but kept here for the other paths.
     */
    private void assertAccountOk(User user) {
        if (user.isLocked())  throw new org.springframework.security.authentication.LockedException("ACCOUNT_LOCKED");
        if (!user.isActive()) throw new org.springframework.security.authentication.DisabledException("ACCOUNT_DISABLED");
    }
}