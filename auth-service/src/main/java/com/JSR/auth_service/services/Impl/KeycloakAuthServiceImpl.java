
package com.JSR.auth_service.services.Impl;

import com.JSR.auth_service.clients.*;
import com.JSR.auth_service.dto.*;
import com.JSR.auth_service.services.KeycloakAuthService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakAuthServiceImpl implements KeycloakAuthService {

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    @Value("${keycloak.client-id:spring-cloud-client}")
    private String clientId;

    // Feign Clients
    private final KeycloakTokenClient keycloakTokenClient;
    private final KeycloakUserInfoClient keycloakUserInfoClient;
    private final KeycloakDiscoveryClient keycloakDiscoveryClient;

    private Keycloak getKeycloakAdminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakServerUrl)
                .realm("master")
                .clientId("admin-cli")
                .grantType(OAuth2Constants.PASSWORD)
                .username(adminUsername)
                .password(adminPassword)
                .build();
    }

    @Override
    public SignupResponse createUser(SignupRequest request) {
        log.info("Creating user in Keycloak: {}", request.getEmail());

        Keycloak keycloak = null;
        try {
            keycloak = getKeycloakAdminClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Validate passwords match
            if (!request.getPassword().equals(request.getConfirmPassword())) {
                throw new IllegalArgumentException("Passwords do not match");
            }

            // Check if user already exists
            if (checkEmailExists(request.getEmail())) {
                throw new RuntimeException("User with this email already exists");
            }

            // Split full name
            String[] nameParts = request.getFullName().trim().split("\\s+", 2);
            String firstName = nameParts[0];
            String lastName = nameParts.length > 1 ? nameParts[1] : "";

            // Generate username from email
            String username = request.getEmail().split("@")[0];

            // Create user representation
            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            user.setEmail(request.getEmail());
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEnabled(true);
            user.setEmailVerified(true);

            // Set credentials
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(request.getPassword());
            credential.setTemporary(false);
            user.setCredentials(List.of(credential));

            // Create user
            Response response = usersResource.create(user);

            if (response.getStatus() == 201) {
                // Extract user ID
                String location = response.getLocation().toString();
                String userId = location.substring(location.lastIndexOf('/') + 1);

                log.info("User created successfully with ID: {}", userId);

                return SignupResponse.builder()
                        .userId(userId)
                        .email(request.getEmail())
                        .fullName(request.getFullName())
                        .requiresEmailVerification(false)
                        .build();
            } else {
                String errorMessage = response.readEntity(String.class);
                log.error("Failed to create user: {}", errorMessage);
                throw new RuntimeException("Failed to create user: " + errorMessage);
            }

        } catch (Exception e) {
            log.error("Error creating user: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create user: " + e.getMessage());
        } finally {
            if (keycloak != null) {
                keycloak.close();
            }
        }
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Logging in user: {}", request.getEmail());

        try {
            // Prepare form data
            Map<String, String> formData = new LinkedHashMap<>();
            formData.put("client_id", clientId);
            formData.put("grant_type", "password");
            formData.put("username", request.getEmail());
            formData.put("password", request.getPassword());
            formData.put("scope", "openid email profile");

            log.debug("Attempting login for user: {}", request.getEmail());

            // Use Feign client
            Map<String, Object> tokenData = keycloakTokenClient.getToken(formData);

            // Get user info
            String accessToken = (String) tokenData.get("access_token");
            UserInfoResponse userInfo = getUserInfo(accessToken);

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken((String) tokenData.get("refresh_token"))
                    .tokenType((String) tokenData.get("token_type"))
                    .expiresIn(((Number) tokenData.get("expires_in")).longValue())
                    .refreshExpiresIn(((Number) tokenData.get("refresh_expires_in")).longValue())
                    .scope((String) tokenData.get("scope"))
                    .user(LoginResponse.UserInfo.builder()
                            .userId(userInfo.getUserId())
                            .email(userInfo.getEmail())
                            .username(userInfo.getUsername())
                            .fullName(userInfo.getFullName())
                            .roles(userInfo.getRoles())
                            .emailVerified(userInfo.isEmailVerified())
                            .build())
                    .build();

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage(), e);
            throw new RuntimeException("Invalid username or password");
        }
    }

    @Override
    public TokenValidationResponse validateToken(String token) {
        log.debug("Validating token");

        try {
            // Prepare auth header for client credentials
            String authHeader = "Basic " + Base64.getEncoder()
                    .encodeToString((clientId + ":" + getClientSecret()).getBytes());

            // Prepare form data
            Map<String, String> formData = new LinkedHashMap<>();
            formData.put("token", token);
            formData.put("token_type_hint", "access_token");

            // Use Feign client
            Map<String, Object> introspectData = keycloakTokenClient.introspectToken(authHeader, formData);
            boolean active = Boolean.TRUE.equals(introspectData.get("active"));

            if (active) {
                return TokenValidationResponse.builder()
                        .valid(true)
                        .userId((String) introspectData.get("sub"))
                        .email((String) introspectData.get("email"))
                        .username((String) introspectData.get("preferred_username"))
                        .roles((List<String>) ((Map<String, Object>) introspectData.get("realm_access")).get("roles"))
                        .expiresAt(Instant.ofEpochSecond(((Number) introspectData.get("exp")).longValue()))
                        .issuedAt(Instant.ofEpochSecond(((Number) introspectData.get("iat")).longValue()))
                        .build();
            }

            return TokenValidationResponse.builder()
                    .valid(false)
                    .errorMessage("Token is invalid or expired")
                    .build();

        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage(), e);
            return TokenValidationResponse.builder()
                    .valid(false)
                    .errorMessage("Token validation failed: " + e.getMessage())
                    .build();
        }
    }

    @Override
    public void logout(String token, boolean allDevices) {
        log.info("Logging out user");

        try {
            // Extract refresh token from the current session (simplified)
            String refreshToken = extractRefreshToken(token);

            // Prepare form data
            Map<String, String> formData = new LinkedHashMap<>();
            formData.put("client_id", clientId);
            formData.put("refresh_token", refreshToken);

            // Use Feign client
            keycloakTokenClient.logout(formData);

        } catch (Exception e) {
            log.warn("Logout failed: {}", e.getMessage(), e);
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
    }

    @Override
    public void sendPasswordResetEmail(String email) {
        log.info("Sending password reset email to: {}", email);

        Keycloak keycloak = null;
        try {
            keycloak = getKeycloakAdminClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Find user by email
            List<UserRepresentation> users = usersResource.searchByEmail(email, true);

            if (users.isEmpty()) {
                throw new RuntimeException("User not found");
            }

            String userId = users.get(0).getId();
            UserResource userResource = usersResource.get(userId);

            // Send password reset email
            userResource.executeActionsEmail(List.of("UPDATE_PASSWORD"));

            log.info("Password reset email sent to: {}", email);

        } catch (Exception e) {
            log.error("Failed to send password reset email: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to send password reset email");
        } finally {
            if (keycloak != null) {
                keycloak.close();
            }
        }
    }

    @Override
    public void resendVerificationEmail(String email) {
        log.info("Resending verification email to: {}", email);

        Keycloak keycloak = null;
        try {
            keycloak = getKeycloakAdminClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Find user by email
            List<UserRepresentation> users = usersResource.searchByEmail(email, true);

            if (users.isEmpty()) {
                throw new RuntimeException("User not found");
            }

            String userId = users.get(0).getId();
            UserResource userResource = usersResource.get(userId);

            // Send verification email
            userResource.sendVerifyEmail();

            log.info("Verification email resent to: {}", email);

        } catch (Exception e) {
            log.error("Failed to resend verification email: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to resend verification email");
        } finally {
            if (keycloak != null) {
                keycloak.close();
            }
        }
    }

    @Override
    public UserInfoResponse getUserInfo(String token) {
        log.debug("Getting user info");

        try {
            // Use Feign client
            Map<String, Object> userInfoData = keycloakUserInfoClient.getUserInfo("Bearer " + token);

            log.debug("User info response: {}", userInfoData);

            // Extract roles from the token
            List<String> roles = extractRoles(token);

            return UserInfoResponse.builder()
                    .userId(getStringValue(userInfoData, "sub"))
                    .email(getStringValue(userInfoData, "email"))
                    .username(getStringValue(userInfoData, "preferred_username"))
                    .fullName(getStringValue(userInfoData, "name"))
                    .firstName(getStringValue(userInfoData, "given_name"))
                    .lastName(getStringValue(userInfoData, "family_name"))
                    .emailVerified(getBooleanValue(userInfoData, "email_verified"))
                    .roles(roles)
                    .attributes(userInfoData)
                    .build();

        } catch (Exception e) {
            log.error("Failed to get user info: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    @Override
    public TokenResponse refreshToken(String refreshToken) {
        log.debug("Refreshing token");

        try {
            // Prepare form data
            Map<String, String> formData = new LinkedHashMap<>();
            formData.put("client_id", clientId);
            formData.put("grant_type", "refresh_token");
            formData.put("refresh_token", refreshToken);

            // Use Feign client
            Map<String, Object> tokenData = keycloakTokenClient.refreshToken(formData);

            return TokenResponse.builder()
                    .accessToken((String) tokenData.get("access_token"))
                    .refreshToken((String) tokenData.get("refresh_token"))
                    .tokenType((String) tokenData.get("token_type"))
                    .expiresIn(((Number) tokenData.get("expires_in")).longValue())
                    .refreshExpiresIn(((Number) tokenData.get("refresh_expires_in")).longValue())
                    .scope((String) tokenData.get("scope"))
                    .build();

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            throw new RuntimeException("Invalid refresh token");
        }
    }

    @Override
    public boolean checkEmailExists(String email) {
        log.debug("Checking if email exists: {}", email);

        Keycloak keycloak = null;
        try {
            keycloak = getKeycloakAdminClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            List<UserRepresentation> users = usersResource.searchByEmail(email, true);
            return !users.isEmpty();

        } catch (Exception e) {
            log.error("Error checking email: {}", e.getMessage(), e);
            return false;
        } finally {
            if (keycloak != null) {
                keycloak.close();
            }
        }
    }

    @Override
    public HealthCheckResponse healthCheck() {
        log.debug("Performing health check");

        try {
            // Use Feign client
            Map<String, Object> config = keycloakDiscoveryClient.getConfiguration();

            boolean keycloakHealthy = config != null && !config.isEmpty();

            return HealthCheckResponse.builder()
                    .serviceHealthy(true)
                    .keycloakHealthy(keycloakHealthy)
                    .timestamp(Instant.now())
                    .keycloakVersion(keycloakHealthy ? "unknown" : "unavailable")
                    .keycloakRealm(realm)
                    .build();

        } catch (Exception e) {
            log.error("Health check failed: {}", e.getMessage(), e);
            return HealthCheckResponse.builder()
                    .serviceHealthy(false)
                    .keycloakHealthy(false)
                    .timestamp(Instant.now())
                    .keycloakRealm(realm)
                    .build();
        }
    }

    // Helper methods
    private String getStringValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }

    private boolean getBooleanValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return Boolean.TRUE.equals(value);
    }

    private List<String> extractRoles(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return Collections.emptyList();

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(payload);

            JsonNode realmAccess = jsonNode.path("realm_access");
            if (!realmAccess.isMissingNode()) {
                JsonNode rolesNode = realmAccess.path("roles");
                if (rolesNode.isArray()) {
                    List<String> roles = new ArrayList<>();
                    for (JsonNode role : rolesNode) {
                        roles.add(role.asText());
                    }
                    log.debug("Extracted roles from token: {}", roles);
                    return roles;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract roles from token: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    private String getClientSecret() {
        return System.getenv("KEYCLOAK_CLIENT_SECRET");
    }

    private String extractRefreshToken(String accessToken) {
        // In a real implementation, you'd store refresh tokens securely
        // This is a simplified version
        return "refresh_token_placeholder";
    }
}