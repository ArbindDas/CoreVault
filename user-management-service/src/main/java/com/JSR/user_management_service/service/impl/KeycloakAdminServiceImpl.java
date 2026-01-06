
package com.JSR.user_management_service.service.impl;

import com.JSR.user_management_service.clients.KeycloakAdminClient;
import com.JSR.user_management_service.clients.TokenClient;
import com.JSR.user_management_service.dto.CreateUserRequest;
import com.JSR.user_management_service.dto.UpdateUserRequest;
import com.JSR.user_management_service.dto.UserResponse;
import com.JSR.user_management_service.exception.KeycloakException;
import com.JSR.user_management_service.exception.UserNotFoundException;
import com.JSR.user_management_service.service.KeycloakAdminService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakAdminServiceImpl implements KeycloakAdminService {

    private final KeycloakAdminClient keycloakAdminClient;
    private final TokenClient tokenClient;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    @Value("${keycloak.resource}")
    private String clientId;

    private static final String ADMIN_CLI = "admin-cli";
    private static final String GRANT_TYPE = "password";
    private static final String BEARER_PREFIX = "Bearer ";

    private String adminToken;
    private long tokenExpiryTime;


    public void init() {
        try {
            refreshAdminToken();
            log.info("Keycloak Admin Service initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize Keycloak Admin Service", e);
            throw new KeycloakException("Failed to initialize Keycloak Admin Service", e);
        }
    }


    private synchronized void refreshAdminToken() {
        log.info("Refreshing admin token for username: {}", adminUsername);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", ADMIN_CLI);
        formData.add("username", adminUsername);
        formData.add("password", adminPassword);
        formData.add("grant_type", GRANT_TYPE);

        try {
            // ✅ CRITICAL: Use "master" realm for admin tokens, not your custom realm
            Map<String, Object> tokenResponse = tokenClient.getAdminToken("master", formData);

            if (tokenResponse != null && tokenResponse.containsKey("access_token")) {
                this.adminToken = (String) tokenResponse.get("access_token");
                long expiresIn = ((Number) tokenResponse.get("expires_in")).longValue() * 1000;
                this.tokenExpiryTime = System.currentTimeMillis() + expiresIn - 60000;

                log.info("✅ Admin token refreshed successfully, expires in {} seconds", expiresIn / 1000);
                log.debug("Token prefix: {}", adminToken.substring(0, Math.min(20, adminToken.length())) + "...");
            } else {
                log.error("❌ Failed to obtain admin token: Invalid response from Keycloak");
                log.error("Response keys: {}", tokenResponse != null ? tokenResponse.keySet() : "null");
                throw new KeycloakException("Invalid token response from Keycloak");
            }
        } catch (Exception e) {
            log.error("❌ Failed to refresh admin token. Username: {}, Error: {}",
                    adminUsername, e.getMessage(), e);
            throw new KeycloakException("Failed to obtain admin token from Keycloak", e);
        }
    }

    public String getAdminToken() {
        if (adminToken == null || System.currentTimeMillis() >= tokenExpiryTime) {
            refreshAdminToken();
        }
        return BEARER_PREFIX + adminToken;
    }

    @Override
    public List<UserResponse> getAllUsers() {
        try {
            String token = getAdminToken();
            ResponseEntity<List<Map<String, Object>>> response = keycloakAdminClient.getAllUsers(realm, token);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody().stream()
                        .map(this::mapToUserResponse)
                        .toList();
            }

            throw new KeycloakException("Failed to retrieve users from Keycloak");

        } catch (Exception e) {
            log.error("Error retrieving all users", e);
            throw new KeycloakException("Failed to retrieve users", e);
        }
    }

    @Override
    public UserResponse getUserById(String userId) {
        try {
            String token = getAdminToken();
            ResponseEntity<Map<String, Object>> response = keycloakAdminClient.getUserById(realm, userId, token);

            if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                throw new UserNotFoundException("User not found with ID: " + userId);
            }

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return mapToUserResponse(response.getBody());
            }

            throw new KeycloakException("Failed to retrieve user with ID: " + userId);

        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error retrieving user with ID: {}", userId, e);
            throw new KeycloakException("Failed to retrieve user", e);
        }
    }

    @Override
    public String createUser(CreateUserRequest request) {
        try {
            String token = getAdminToken();
            Map<String, Object> userData = buildUserData(request);

            ResponseEntity<Void> response = keycloakAdminClient.createUser(realm, token, userData);

            if (response.getStatusCode().is2xxSuccessful()) {
                // Extract user ID from location header
                String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                if (location != null) {
                    String userId = location.substring(location.lastIndexOf('/') + 1);
                    log.info("User created successfully with ID: {}", userId);
                    return userId;
                }
            }

            log.error("Failed to create user. Status: {}", response.getStatusCode());
            throw new KeycloakException("Failed to create user in Keycloak");

        } catch (Exception e) {
            log.error("Error creating user", e);
            throw new KeycloakException("Failed to create user", e);
        }
    }

    @Override
    public void updateUser(String userId, UpdateUserRequest request) {
        try {
            String token = getAdminToken();

            Map<String, Object> userData = new HashMap<>();
            if (request.getUsername() != null) userData.put("username", request.getUsername());
            if (request.getEmail() != null) userData.put("email", request.getEmail());
            if (request.getFirstName() != null) userData.put("firstName", request.getFirstName());
            if (request.getLastName() != null) userData.put("lastName", request.getLastName());
            if (request.getEmailVerified() != null) userData.put("emailVerified", request.getEmailVerified());
            if (request.getEnabled() != null) userData.put("enabled", request.getEnabled());

            ResponseEntity<Void> response = keycloakAdminClient.updateUser(realm, userId, token, userData);

            if (!response.getStatusCode().is2xxSuccessful()) {
                if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                    throw new UserNotFoundException("User not found with ID: " + userId);
                }
                throw new KeycloakException("Failed to update user");
            }

            log.info("User updated successfully with ID: {}", userId);

        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error updating user with ID: {}", userId, e);
            throw new KeycloakException("Failed to update user", e);
        }
    }

    @Override
    public void deleteUser(String userId) {
        try {
            String token = getAdminToken();
            ResponseEntity<Void> response = keycloakAdminClient.deleteUser(realm, userId, token);

            if (!response.getStatusCode().is2xxSuccessful()) {
                if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                    throw new UserNotFoundException("User not found with ID: " + userId);
                }
                throw new KeycloakException("Failed to delete user");
            }

            log.info("User deleted successfully with ID: {}", userId);

        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error deleting user with ID: {}", userId, e);
            throw new KeycloakException("Failed to delete user", e);
        }
    }

    @Override
    public void sendVerificationEmail(String userId) {
        try {
            String token = getAdminToken();
            ResponseEntity<Void> response = keycloakAdminClient.sendVerificationEmail(realm, userId, token, clientId);

            if (!response.getStatusCode().is2xxSuccessful()) {
                if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                    throw new UserNotFoundException("User not found with ID: " + userId);
                }
                throw new KeycloakException("Failed to send verification email");
            }

            log.info("Verification email sent successfully for user ID: {}", userId);

        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error sending verification email for user ID: {}", userId, e);
            throw new KeycloakException("Failed to send verification email", e);
        }
    }

    @Override
    public void resetPassword(String userId, String newPassword, boolean temporary) {
        try {
            String token = getAdminToken();

            Map<String, Object> passwordData = new HashMap<>();
            passwordData.put("type", "password");
            passwordData.put("value", newPassword);
            passwordData.put("temporary", temporary);

            ResponseEntity<Void> response = keycloakAdminClient.resetPassword(realm, userId, token, passwordData);

            if (!response.getStatusCode().is2xxSuccessful()) {
                if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                    throw new UserNotFoundException("User not found with ID: " + userId);
                }
                throw new KeycloakException("Failed to reset password");
            }

            log.info("Password reset successfully for user ID: {}", userId);

        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error resetting password for user ID: {}", userId, e);
            throw new KeycloakException("Failed to reset password", e);
        }
    }

//    private Map<String, Object> buildUserData(CreateUserRequest request) {
//        Map<String, Object> userData = new HashMap<>();
//        userData.put("username", request.getUsername());
//        userData.put("email", request.getEmail());
//        userData.put("firstName", request.getFirstName());
//        userData.put("lastName", request.getLastName());
//        userData.put("enabled", request.isEnabled());
//        userData.put("emailVerified", request.isEmailVerified());
//
//        // Credentials
//        Map<String, Object> credentials = new HashMap<>();
//        credentials.put("type", "password");
//        credentials.put("value", request.getPassword());
//        credentials.put("temporary", request.isTemporaryPassword());
//        userData.put("credentials", List.of(credentials));
//
//        // Required actions
//        List<String> requiredActions = new ArrayList<>();
//        if (!request.isEmailVerified()) {
//            requiredActions.add("VERIFY_EMAIL");
//        }
//        if (request.isTemporaryPassword()) {
//            requiredActions.add("UPDATE_PASSWORD");
//        }
//
//        if (!requiredActions.isEmpty()) {
//            userData.put("requiredActions", requiredActions);
//        }
//
//        return userData;
//    }



    private Map<String, Object> buildUserData(CreateUserRequest request) {
        Map<String, Object> userData = new HashMap<>();

        // Split fullName into firstName and lastName
        String fullName = request.getFullName();
        String firstName = "";
        String lastName = "";

        if (fullName != null && !fullName.trim().isEmpty()) {
            String[] nameParts = fullName.trim().split("\\s+", 2);
            firstName = nameParts[0];
            lastName = nameParts.length > 1 ? nameParts[1] : "";
        }

        // Use email as username (common practice)
        userData.put("username", request.getEmail());
        userData.put("email", request.getEmail());
        userData.put("firstName", firstName);
        userData.put("lastName", lastName);
        userData.put("enabled", true); // Default to enabled
        userData.put("emailVerified", true); // Default to not verified

        // Credentials - password from request
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("type", "password");
        credentials.put("value", request.getPassword());
        credentials.put("temporary", false); // Assuming password is not temporary
        userData.put("credentials", List.of(credentials));

        // Required actions
        List<String> requiredActions = new ArrayList<>();

        // Always require email verification for new users
        requiredActions.add("VERIFY_EMAIL");

        // If you want to force password change on first login
        // requiredActions.add("UPDATE_PASSWORD");

        if (!requiredActions.isEmpty()) {
            userData.put("requiredActions", requiredActions);
        }

        return userData;
    }

    private UserResponse mapToUserResponse(Map<String, Object> userMap) {
        if (userMap == null) {
            return null;
        }

        try {
            return UserResponse.builder()
                    .id(getStringValue(userMap, "id"))
                    .username(getStringValue(userMap, "username"))
                    .email(getStringValue(userMap, "email"))
                    .firstName(getStringValue(userMap, "firstName"))
                    .lastName(getStringValue(userMap, "lastName"))
                    .emailVerified(getBooleanValue(userMap, "emailVerified"))
                    .enabled(getBooleanValue(userMap, "enabled"))
                    .createdTimestamp(getLongValue(userMap, "createdTimestamp"))
                    .requiredActions(getListValue(userMap, "requiredActions"))
                    .attributes(getAttributes(userMap))
                    .build();
        } catch (Exception e) {
            log.error("Error mapping user data to UserResponse", e);
            throw new KeycloakException("Failed to map user data", e);
        }
    }

    private String getStringValue(Map<String, Object> map, String key) {
        return map.containsKey(key) ? (String) map.get(key) : null;
    }

    private Boolean getBooleanValue(Map<String, Object> map, String key) {
        return map.containsKey(key) ? (Boolean) map.get(key) : false;
    }

    private Long getLongValue(Map<String, Object> map, String key) {
        if (!map.containsKey(key)) return null;
        Object value = map.get(key);
        return convertToLong(value);
    }

    @SuppressWarnings("unchecked")
    private List<String> getListValue(Map<String, Object> map, String key) {
        return map.containsKey(key) ? (List<String>) map.get(key) : Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    private Map<String, List<String>> getAttributes(Map<String, Object> map) {
        return map.containsKey("attributes") ? (Map<String, List<String>>) map.get("attributes") : Collections.emptyMap();
    }

    private Long convertToLong(Object value) {
        if (value == null) return null;

        if (value instanceof Number) {
            return ((Number) value).longValue();
        } else if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                log.warn("Failed to parse long value: {}", value);
                return null;
            }
        }
        return null;
    }
}