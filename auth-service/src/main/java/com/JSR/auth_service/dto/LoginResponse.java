package com.JSR.auth_service.dto;

import lombok.Builder;

import java.util.Set;

@Builder
public record LoginResponse(

        String token,
        String tokenType,
        Long userId,
        String fullName,
        String email,
        Set<String> roles // Use role names instead of Role entities
)
{
}
