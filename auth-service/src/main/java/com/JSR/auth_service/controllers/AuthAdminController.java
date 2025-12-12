package com.JSR.auth_service.controllers;

import com.JSR.auth_service.dto.ApiResponseWrapper;
import com.JSR.auth_service.services.TokenBlacklistService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/admin")
@Slf4j
public class AuthAdminController {

    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public AuthAdminController(TokenBlacklistService tokenBlacklistService) {
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @PostMapping("/cleanup/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Void>> cleanupUserTokens(
            @PathVariable String username) {

        log.info("Manual token cleanup requested for user: {}", username);
        tokenBlacklistService.cleanupExpiredTokensFromSet(username);

        ApiResponseWrapper<Void> response = ApiResponseWrapper.success(
                null,
                "Token cleanup completed for user: " + username,
                HttpStatus.OK.value()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/cleanup-all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Void>> cleanupAllUsersTokens() {

        log.info("Manual cleanup for ALL users requested");
        tokenBlacklistService.scheduledCleanupAllUsers();

        ApiResponseWrapper<Void> response = ApiResponseWrapper.success(
                null,
                "Token cleanup initiated for all users",
                HttpStatus.OK.value()
        );

        return ResponseEntity.ok(response);
    }
}