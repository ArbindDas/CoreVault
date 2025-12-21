package com.JSR.user_management_service.controllers;
import com.JSR.user_management_service.dto.ApiResponse;
import com.JSR.user_management_service.dto.CreateUserRequest;
import com.JSR.user_management_service.dto.UpdateUserRequest;
import com.JSR.user_management_service.dto.UserResponse;
import com.JSR.user_management_service.service.KeycloakAdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin/users")
@Slf4j
@RequiredArgsConstructor
public class AdminController {

    private final KeycloakAdminService keycloakAdminService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        log.info("Admin requested all users");
        List<UserResponse> users = keycloakAdminService.getAllUsers();

        return ResponseEntity.ok(
                ApiResponse.<List<UserResponse>>builder()
                        .success(true)
                        .message("Users retrieved successfully")
                        .data(users)
                        .build()
        );
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable String userId) {
        log.info("Admin requested user with ID: {}", userId);
        UserResponse user = keycloakAdminService.getUserById(userId);

        return ResponseEntity.ok(
                ApiResponse.<UserResponse>builder()
                        .success(true)
                        .message("User retrieved successfully")
                        .data(user)
                        .build()
        );
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> createUser(@Valid @RequestBody CreateUserRequest request) {
        log.info("Admin creating new user: {}", request.getEmail());
        String userId = keycloakAdminService.createUser(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.<String>builder()
                        .success(true)
                        .message("User created successfully")
                        .data(userId)
                        .build());
    }

    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> updateUser(
            @PathVariable String userId,
            @Valid @RequestBody UpdateUserRequest request) {

        log.info("Admin updating user with ID: {}", userId);
        keycloakAdminService.updateUser(userId, request);

        return ResponseEntity.ok(
                ApiResponse.<Void>builder()
                        .success(true)
                        .message("User updated successfully")
                        .build()
        );
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable String userId) {
        log.info("Admin deleting user with ID: {}", userId);
        keycloakAdminService.deleteUser(userId);

        return ResponseEntity.ok(
                ApiResponse.<Void>builder()
                        .success(true)
                        .message("User deleted successfully")
                        .build()
        );
    }

    @PostMapping("/{userId}/send-verification")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> sendVerificationEmail(@PathVariable String userId) {
        log.info("Admin sending verification email for user: {}", userId);
        keycloakAdminService.sendVerificationEmail(userId);

        return ResponseEntity.ok(
                ApiResponse.<Void>builder()
                        .success(true)
                        .message("Verification email sent")
                        .build()
        );
    }

    @PostMapping("/{userId}/reset-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @PathVariable String userId,
            @RequestParam String newPassword,
            @RequestParam(defaultValue = "true") boolean temporary) {

        log.info("Admin resetting password for user: {}", userId);
        keycloakAdminService.resetPassword(userId, newPassword, temporary);

        return ResponseEntity.ok(
                ApiResponse.<Void>builder()
                        .success(true)
                        .message("Password reset successfully")
                        .build()
        );
    }
}