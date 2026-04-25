package com.example.jwt_authenticator.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Map;

/**
 * Unified error response body.
 *
 * Used by both GlobalExceptionHandler and JwtAuthenticationFailureHandler.
 * All error responses share the same shape — 'errorCode' is the single
 * field for machine-readable error identifiers.
 *
 * 'error' contains the HTTP status name (e.g. "CONFLICT", "BAD_REQUEST").
 * 'errorCode' contains the application-level code (e.g. "VALIDATION_ERROR",
 *             "USER_ALREADY_EXISTS", "TOKEN_EXPIRED").
 *
 * FIX: Renamed 'code' → 'errorCode' to match the field name used by
 * JwtAuthenticationFailureHandler. Previously the two error sources
 * emitted different field names for the same concept, forcing the frontend
 * to handle both 'code' and 'errorCode'.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        Instant timestamp,
        int     status,
        String  error,      // HTTP status name — e.g. "CONFLICT", "UNAUTHORIZED"
        String  errorCode,  // App-level code  — e.g. "VALIDATION_ERROR", "TOKEN_EXPIRED"
        String  message,    // Human-readable message for the client
        String  path,
        String  traceId,
        Map<String, Object> details  // Optional — used for field-level validation errors
) {
    /** Convenience constructor without details (most error cases). */
    public ApiError(Instant timestamp, int status, String error, String errorCode,
                    String message, String path, String traceId) {
        this(timestamp, status, error, errorCode, message, path, traceId, null);
    }
}