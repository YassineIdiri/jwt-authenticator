package com.example.jwt_authenticator.controller;

import com.example.jwt_authenticator.dto.*;
import com.example.jwt_authenticator.security.CustomUserDetails;
import com.example.jwt_authenticator.security.RefreshCookieFactory;
import com.example.jwt_authenticator.service.AuthService;
import com.example.jwt_authenticator.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshCookieFactory refreshCookieFactory;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        RegisterResponse response = authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req, HttpServletRequest httpReq) {
        var result = authService.login(req, httpReq);

        return ResponseEntity.ok()
                .header("Set-Cookie", refreshCookieFactory.create(result.refreshTokenRaw(), result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest httpReq) {
        String refreshToken = refreshCookieFactory.readFrom(httpReq);
        var result = authService.refresh(refreshToken, httpReq);

        return ResponseEntity.ok()
                .header("Set-Cookie", refreshCookieFactory.create(result.refreshTokenRaw(), result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest httpReq) {
        String refreshToken = refreshCookieFactory.readFrom(httpReq);
        authService.logout(refreshToken);

        return ResponseEntity.noContent()
                .header("Set-Cookie", refreshCookieFactory.delete().toString())
                .build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest httpReq) {
        String refreshToken = refreshCookieFactory.readFrom(httpReq);
        authService.logoutAll(refreshToken);

        return ResponseEntity.noContent()
                .header("Set-Cookie", refreshCookieFactory.delete().toString())
                .build();
    }

    @PostMapping("/oauth2/exchange")
    public ResponseEntity<AuthResponse> exchangeOAuth2Code(
            @Valid @RequestBody OAuth2ExchangeRequest req,
            HttpServletRequest httpReq) {

        var result = authService.exchangeOAuth2Code(req.code(), httpReq);

        return ResponseEntity.ok()
                .header("Set-Cookie",
                        refreshCookieFactory.create(
                                result.refreshTokenRaw(),
                                result.refreshExpiresAt()).toString())
                .body(AuthService.toResponse(result));
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getSessions(HttpServletRequest httpReq) {
        Long userId = authService.extractUserIdFromContext();
        String currentToken = refreshCookieFactory.readFrom(httpReq);
        return ResponseEntity.ok(refreshTokenService.getActiveSessions(userId, currentToken));
    }

    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<Void> revokeSession(@PathVariable Long id) {
        refreshTokenService.revokeSession(id, authService.extractUserIdFromContext());
        return ResponseEntity.noContent().build();
    }
}
