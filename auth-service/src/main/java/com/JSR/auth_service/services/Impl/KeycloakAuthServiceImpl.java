package com.JSR.auth_service.services.Impl;

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
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;


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

    private final RestTemplate restTemplate;



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
            user.setEmailVerified(true);  // ✅ Set to true for development

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
                        .requiresEmailVerification(false)  // ✅ Set to false
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
            String tokenUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("grant_type", "password");
            body.add("username", request.getEmail());
            body.add("password", request.getPassword());
            body.add("scope", "openid email profile");

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            log.debug("Attempting login for user: {}", request.getEmail());

            ResponseEntity<Map> response = restTemplate.exchange(
                    tokenUrl, HttpMethod.POST, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

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
            } else {
                throw new RuntimeException("Invalid credentials");
            }

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            throw new RuntimeException("Invalid username or password");
        }
    }

    @Override
    public TokenValidationResponse validateToken(String token) {
        log.debug("Validating token");

        try {
            // Call Keycloak introspection endpoint
            String introspectionUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token/introspect";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(clientId, getClientSecret());

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            body.add("token_type_hint", "access_token");

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    introspectionUrl, HttpMethod.POST, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> introspectData = response.getBody();
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
            }

            return TokenValidationResponse.builder()
                    .valid(false)
                    .errorMessage("Token is invalid or expired")
                    .build();

        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage());
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
            String logoutUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("refresh_token", extractRefreshToken(token));

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            restTemplate.exchange(logoutUrl, HttpMethod.POST, entity, Void.class);

        } catch (Exception e) {
            log.warn("Logout failed: {}", e.getMessage());
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


//    @Override
//    public UserInfoResponse getUserInfo(String token) {
//        log.debug("Getting user info");
//
//        try {
//            String userInfoUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";
//
//            HttpHeaders headers = new HttpHeaders();
//            headers.setBearerAuth(token);
//
//            HttpEntity<Void> entity = new HttpEntity<>(headers);
//
//            ResponseEntity<Map> response = restTemplate.exchange(
//                    userInfoUrl, HttpMethod.GET, entity, Map.class);
//
//            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
//                Map<String, Object> userInfoData = response.getBody();
//
//                log.debug("User info response: {}", userInfoData);
//
//                return UserInfoResponse.builder()
//                        .userId(getStringValue(userInfoData, "sub"))
//                        .email(getStringValue(userInfoData, "email"))
//                        .username(getStringValue(userInfoData, "preferred_username"))
//                        .fullName(getStringValue(userInfoData, "name"))
//                        .firstName(getStringValue(userInfoData, "given_name"))
//                        .lastName(getStringValue(userInfoData, "family_name"))
//                        .emailVerified(getBooleanValue(userInfoData, "email_verified"))
//                        .roles(extractRoles(userInfoData))
//                        .attributes(userInfoData)
//                        .build();
//            }
//
//            throw new RuntimeException("Failed to get user info");
//
//        } catch (Exception e) {
//            log.error("Failed to get user info: {}", e.getMessage(), e);
//            throw new RuntimeException("Failed to get user info: " + e.getMessage());
//        }
//    }



    @Override
    public UserInfoResponse getUserInfo(String token) {
        log.debug("Getting user info");

        try {
            String userInfoUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    userInfoUrl, HttpMethod.GET, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userInfoData = response.getBody();

                log.debug("User info response: {}", userInfoData);

                // ✅ Get roles from the token, not from userinfo
                List<String> roles = extractRoles(token);

                return UserInfoResponse.builder()
                        .userId(getStringValue(userInfoData, "sub"))
                        .email(getStringValue(userInfoData, "email"))
                        .username(getStringValue(userInfoData, "preferred_username"))
                        .fullName(getStringValue(userInfoData, "name"))
                        .firstName(getStringValue(userInfoData, "given_name"))
                        .lastName(getStringValue(userInfoData, "family_name"))
                        .emailVerified(getBooleanValue(userInfoData, "email_verified"))
                        .roles(roles) // ✅ Now contains ["ADMIN", ...]
                        .attributes(userInfoData)
                        .build();
            }

            throw new RuntimeException("Failed to get user info");

        } catch (Exception e) {
            log.error("Failed to get user info: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    // ✅ Helper methods for safe extraction
    private String getStringValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }

    private boolean getBooleanValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return Boolean.TRUE.equals(value);
    }

//    private List<String> extractRoles(Map<String, Object> userInfoData) {
//        try {
//            Object realmAccessObj = userInfoData.get("realm_access");
//            if (realmAccessObj instanceof Map) {
//                Map<String, Object> realmAccess = (Map<String, Object>) realmAccessObj;
//                Object rolesObj = realmAccess.get("roles");
//                if (rolesObj instanceof List) {
//                    return (List<String>) rolesObj;
//                }
//            }
//        } catch (Exception e) {
//            log.warn("Failed to extract roles: {}", e.getMessage());
//        }
//        return Collections.emptyList();
//    }


    private List<String> extractRoles(String token) {
        try {
            // Decode the JWT token to get roles
            String[] parts = token.split("\\.");
            if (parts.length < 2) return Collections.emptyList();

            // Decode the payload (middle part)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(payload);

            // Extract roles from realm_access.roles
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


    @Override
    public TokenResponse refreshToken(String refreshToken) {
        log.debug("Refreshing token");

        try {
            String tokenUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("grant_type", "refresh_token");
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    tokenUrl, HttpMethod.POST, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

                return TokenResponse.builder()
                        .accessToken((String) tokenData.get("access_token"))
                        .refreshToken((String) tokenData.get("refresh_token"))
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(((Number) tokenData.get("expires_in")).longValue())
                        .refreshExpiresIn(((Number) tokenData.get("refresh_expires_in")).longValue())
                        .scope((String) tokenData.get("scope"))
                        .build();
            }

            throw new RuntimeException("Failed to refresh token");

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
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
            // Check Keycloak health
            String healthUrl = keycloakServerUrl + "/realms/" + realm + "/.well-known/openid-configuration";

            ResponseEntity<Map> response = restTemplate.exchange(
                    healthUrl, HttpMethod.GET, null, Map.class);

            boolean keycloakHealthy = response.getStatusCode() == HttpStatus.OK;

            return HealthCheckResponse.builder()
                    .serviceHealthy(true)
                    .keycloakHealthy(keycloakHealthy)
                    .timestamp(Instant.now())
                    .keycloakVersion(keycloakHealthy ? "unknown" : "unavailable")
                    .keycloakRealm(realm)
                    .build();

        } catch (Exception e) {
            log.error("Health check failed: {}", e.getMessage());
            return HealthCheckResponse.builder()
                    .serviceHealthy(false)
                    .keycloakHealthy(false)
                    .timestamp(Instant.now())
                    .keycloakRealm(realm)
                    .build();
        }
    }

    private String getClientSecret() {
        // Get client secret from configuration or environment
        // This should be configured in application.yml
        return System.getenv("KEYCLOAK_CLIENT_SECRET");
    }

    private String extractRefreshToken(String accessToken) {
        // In a real implementation, you'd need to store refresh tokens
        // This is a simplified version
        return "refresh_token_placeholder";
    }
}