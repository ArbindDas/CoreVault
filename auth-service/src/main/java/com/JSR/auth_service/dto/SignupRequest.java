package com.JSR.auth_service.dto;

public record SignupRequest(
        String fullName,
        String email,
        String password
) {
}
