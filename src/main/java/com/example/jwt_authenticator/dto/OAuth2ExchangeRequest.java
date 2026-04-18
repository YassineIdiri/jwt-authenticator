package com.example.jwt_authenticator.dto;

import jakarta.validation.constraints.NotBlank;

public record OAuth2ExchangeRequest(
        @NotBlank String code
) {}