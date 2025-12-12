package com.JSR.auth_service.dto;

import lombok.Builder;

// Separate error response
@Builder
public record LoginErrorResponse(
        String error,
        Integer status,
        String timestamp
) {}
