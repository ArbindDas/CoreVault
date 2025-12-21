package com.JSR.user_management_service.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@FeignClient(
        name = "keycloak-admin-client",
        url = "${keycloak.auth-server-url}",
        configuration = com.JSR.user_management_service.config.FeignConfig.class
)
public interface KeycloakAdminClient {

    // Get all users
    @GetMapping("/admin/realms/{realm}/users")
    ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @PathVariable("realm") String realm,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    // Get specific user
    @GetMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Map<String, Object>> getUserById(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    // Create user
    @PostMapping("/admin/realms/{realm}/users")
    ResponseEntity<Void> createUser(
            @PathVariable("realm") String realm,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> userData
    );

    // Update user
    @PutMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Void> updateUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> userData
    );

    // Delete user
    @DeleteMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Void> deleteUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    // Send verification email
    @PutMapping("/admin/realms/{realm}/users/{userId}/send-verify-email")
    ResponseEntity<Void> sendVerificationEmail(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestParam("client_id") String clientId
    );

    // Reset password
    @PutMapping("/admin/realms/{realm}/users/{userId}/reset-password")
    ResponseEntity<Void> resetPassword(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> passwordData
    );
}