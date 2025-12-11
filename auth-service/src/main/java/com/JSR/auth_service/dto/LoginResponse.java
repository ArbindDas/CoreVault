package com.JSR.auth_service.dto;

import java.util.Set;

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
