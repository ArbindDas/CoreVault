package com.JSR.auth_service.dto;

import java.time.LocalDateTime;

public record SignupResponse(
        Long id,
        String fullName,
        String email,
        String password,
        boolean enabled,
        LocalDateTime createAt,
        LocalDateTime updateAt
) {
}
