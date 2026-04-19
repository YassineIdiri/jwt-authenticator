package com.example.jwt_authenticator.security;

import com.example.jwt_authenticator.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Writes a structured JSON 401 response directly from the JWT filter,
 * without depending on Spring Security's AuthenticationEntryPoint.
 *
 * This is the key class that breaks the circular dependency:
 *
 *   BEFORE:  JwtAuthenticationFilter → AuthenticationEntryPoint (defined in SecurityConfig)
 *                                       ↑ SecurityConfig injects JwtAuthenticationFilter
 *            → circular → @Lazy workaround
 *
 *   AFTER:   JwtAuthenticationFilter → JwtAuthenticationFailureHandler (standalone @Component)
 *                                       SecurityConfig → JwtAuthenticationFilter (clean, no cycle)
 *
 * Response shape:
 * {
 *   "timestamp": "2024-01-01T00:00:00Z",
 *   "status":    401,
 *   "errorCode": "TOKEN_EXPIRED",
 *   "message":   "Token has expired",
 *   "path":      "/api/users/me"
 * }
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            ErrorCode errorCode,
            String logMessage
    ) throws IOException {

        // Log with no sensitive data — just error class and path
        log.warn("JWT auth failure [{}] on {} {}", errorCode, request.getMethod(), request.getServletPath());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Generic user-facing message — never expose internal exception details
        String userMessage = toUserMessage(errorCode);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp",  Instant.now().toString());
        body.put("status",     HttpStatus.UNAUTHORIZED.value());
        body.put("errorCode",  errorCode.name());
        body.put("message",    userMessage);
        body.put("path",       request.getServletPath());

        objectMapper.writeValue(response.getWriter(), body);
    }

    private static String toUserMessage(ErrorCode code) {
        return switch (code) {
            case TOKEN_EXPIRED        -> "Authentication token has expired. Please log in again.";
            case INVALID_SIGNATURE    -> "Authentication token signature is invalid.";
            case MALFORMED_TOKEN      -> "Authentication token is malformed.";
            case UNSUPPORTED_TOKEN    -> "Authentication token type is not supported.";
            default                   -> "Authentication token is invalid.";
        };
    }
}