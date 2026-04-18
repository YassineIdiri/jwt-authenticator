package com.example.jwt_authenticator.dto;

import java.time.LocalDateTime;

public record SessionResponse(
        Long id,
        String deviceName,
        String ipAddress,
        LocalDateTime lastUsedAt,
        boolean current
) {}