//package com.JSR.user_management_service.clients;
//
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//import java.util.List;
//import java.util.Map;
//
//@FeignClient(
//        name = "keycloak-admin-client",
//        url = "${keycloak.auth-server-url}",
//        configuration = com.JSR.user_management_service.config.FeignConfig.class
//)
//public interface KeycloakAdminClient {
//
//    // Get all users
//    @GetMapping("/admin/realms/{realm}/users")
//    ResponseEntity<List<Map<String, Object>>> getAllUsers(
//            @PathVariable("realm") String realm,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
//    );
//
//    // Get specific user
//    @GetMapping("/admin/realms/{realm}/users/{userId}")
//    ResponseEntity<Map<String, Object>> getUserById(
//            @PathVariable("realm") String realm,
//            @PathVariable("userId") String userId,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
//    );
//
//    // Create user
//    @PostMapping("/admin/realms/{realm}/users")
//    ResponseEntity<Void> createUser(
//            @PathVariable("realm") String realm,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
//            @RequestBody Map<String, Object> userData
//    );
//
//    // Update user
//    @PutMapping("/admin/realms/{realm}/users/{userId}")
//    ResponseEntity<Void> updateUser(
//            @PathVariable("realm") String realm,
//            @PathVariable("userId") String userId,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
//            @RequestBody Map<String, Object> userData
//    );
//
//    // Delete user
//    @DeleteMapping("/admin/realms/{realm}/users/{userId}")
//    ResponseEntity<Void> deleteUser(
//            @PathVariable("realm") String realm,
//            @PathVariable("userId") String userId,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
//    );
//
//    // Send verification email
//    @PutMapping("/admin/realms/{realm}/users/{userId}/send-verify-email")
//    ResponseEntity<Void> sendVerificationEmail(
//            @PathVariable("realm") String realm,
//            @PathVariable("userId") String userId,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
//            @RequestParam("client_id") String clientId
//    );
//
//    // Reset password
//    @PutMapping("/admin/realms/{realm}/users/{userId}/reset-password")
//    ResponseEntity<Void> resetPassword(
//            @PathVariable("realm") String realm,
//            @PathVariable("userId") String userId,
//            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
//            @RequestBody Map<String, Object> passwordData
//    );
//}

package com.JSR.user_management_service.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

/**
 * Feign client to interact with Keycloak Admin REST API.
 *
 * This interface allows the user-management-service to:
 * - Fetch users
 * - Create, update, delete users
 * - Send verification emails
 * - Reset passwords
 *
 * All calls require an admin access token in the Authorization header.
 */
@FeignClient(
        name = "keycloak-admin-client",
        url = "${keycloak.auth-server-url}",
        configuration = com.JSR.user_management_service.config.FeignConfig.class
)
public interface KeycloakAdminClient {

    /**
     * Fetch all users in a given realm.
     * Useful for:
     * - Admin dashboard listing all users
     * - Syncing users between microservices
     *
     * @param realm the Keycloak realm
     * @param authorization admin bearer token
     * @return list of all users with their properties
     */
    @GetMapping("/admin/realms/{realm}/users")
    ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @PathVariable("realm") String realm,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    /**
     * Fetch a specific user by userId.
     * Useful for:
     * - Viewing detailed user profile
     * - Editing user info
     *
     * @param realm the Keycloak realm
     * @param userId Keycloak user ID
     * @param authorization admin bearer token
     * @return user details as a map
     */
    @GetMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Map<String, Object>> getUserById(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    /**
     * Create a new user in Keycloak.
     * Useful for:
     * - Admin creating users manually
     * - User signup via backend (with admin privileges)
     *
     * @param realm the Keycloak realm
     * @param authorization admin bearer token
     * @param userData user representation (username, email, firstName, lastName, credentials, etc.)
     */
    @PostMapping("/admin/realms/{realm}/users")
    ResponseEntity<Void> createUser(
            @PathVariable("realm") String realm,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> userData
    );

    /**
     * Update an existing user's information.
     * Useful for:
     * - Admin editing user profile
     * - Changing user attributes like email, name, roles
     *
     * @param realm the Keycloak realm
     * @param userId Keycloak user ID
     * @param authorization admin bearer token
     * @param userData updated user fields
     */
    @PutMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Void> updateUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> userData
    );

    /**
     * Delete a user from Keycloak.
     * Useful for:
     * - Admin removing inactive or banned users
     *
     * @param realm the Keycloak realm
     * @param userId Keycloak user ID
     * @param authorization admin bearer token
     */
    @DeleteMapping("/admin/realms/{realm}/users/{userId}")
    ResponseEntity<Void> deleteUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization
    );

    /**
     * Send a verification email to a user.
     * Useful for:
     * - Confirming email after signup
     * - Triggering email verification manually by admin
     *
     * @param realm the Keycloak realm
     * @param userId Keycloak user ID
     * @param authorization admin bearer token
     * @param clientId Keycloak client ID (from which email template is applied)
     */
    @PutMapping("/admin/realms/{realm}/users/{userId}/send-verify-email")
    ResponseEntity<Void> sendVerificationEmail(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestParam("client_id") String clientId
    );

    /**
     * Reset a user's password.
     * Useful for:
     * - Admin-initiated password reset
     * - Sending temporary credentials to users
     *
     * @param realm the Keycloak realm
     * @param userId Keycloak user ID
     * @param authorization admin bearer token
     * @param passwordData map containing password fields (type, value, temporary)
     */
    @PutMapping("/admin/realms/{realm}/users/{userId}/reset-password")
    ResponseEntity<Void> resetPassword(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> passwordData
    );
}
