package com.JSR.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HealthCheckResponse {
    private boolean serviceHealthy;
    private boolean keycloakHealthy;
    private Instant timestamp;
    private String keycloakVersion;
    private String keycloakRealm;
}