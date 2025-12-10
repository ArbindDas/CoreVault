package com.JSR.auth_service.dto;

public record LoginResponse(

        String token,
        String tokenType,
        Long userId,
        String fullName,
        String email,
        java.util.Set<com.JSR.auth_service.entities.Roles> roles
)
{
}
