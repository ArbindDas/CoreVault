package com.JSR.auth_service.dto;

public record UserRequest(
        String fullName,
        String email,
        String password
) {
}
