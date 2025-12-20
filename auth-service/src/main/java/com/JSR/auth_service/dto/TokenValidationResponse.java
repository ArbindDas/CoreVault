package com.JSR.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

// Token DTOs
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    private boolean valid;
    private String userId;
    private String email;
    private String username;
    private List<String> roles;
    private Instant expiresAt;
    private Instant issuedAt;
    private String errorMessage;
}