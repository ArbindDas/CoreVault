//package com.JSR.auth_service.clients;
//
//import com.JSR.auth_service.config.FeignConfig;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.http.MediaType;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestHeader;
//
//import java.util.Map;
//
//@FeignClient(
//        name = "keycloak-token-client",
//        url = "${keycloak.auth-server-url}",
//        configuration = FeignConfig.class
//)
//public interface KeycloakTokenClient {
//
//    @PostMapping(
//            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    Map<String, Object> getToken(@RequestBody Map<String, ?> formData);
//
//    @PostMapping(
//            value = "/realms/${keycloak.realm}/protocol/openid-connect/token/introspect",
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    Map<String, Object> introspectToken(
//            @RequestHeader("Authorization") String authHeader,
//            @RequestBody Map<String, ?> formData
//    );
//
//    @PostMapping(
//            value = "/realms/${keycloak.realm}/protocol/openid-connect/logout",
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    void logout(@RequestBody Map<String, ?> formData);
//
//    @PostMapping(
//            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    Map<String, Object> refreshToken(@RequestBody Map<String, ?> formData);
//}


package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

/**
 * Feign client responsible for interacting with Keycloak's
 * OpenID Connect Token endpoints.
 *
 * Responsibilities:
 * - User login (password grant or client credentials)
 * - Token refresh
 * - Token introspection (validation)
 * - User logout
 *
 * This client acts as the authentication bridge between
 * the Auth Service and Keycloak.
 */
@FeignClient(
        // Logical identifier of this Feign client
        name = "keycloak-token-client",

        // Base URL of Keycloak server (e.g. http://localhost:8080)
        url = "${keycloak.auth-server-url}",

        // Custom Feign configuration (timeouts, logging, encoders)
        configuration = FeignConfig.class
)
public interface KeycloakTokenClient {

    /**
     * 🔐 AUTHENTICATION / TOKEN GENERATION
     *
     * Calls Keycloak's token endpoint to obtain:
     * - access_token
     * - refresh_token
     * - expires_in
     *
     * Common use cases:
     * - User login (password grant)
     * - Client credentials grant
     *
     * Required form parameters (example):
     * - grant_type=password
     * - client_id=auth-client
     * - client_secret=xxxx
     * - username=user@example.com
     * - password=secret
     *
     * Returns:
     * - OAuth2 token response as a Map
     */
    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getToken(@RequestBody Map<String, ?> formData);

    /**
     * 🔍 TOKEN INTROSPECTION
     *
     * Validates whether a token is:
     * - Active
     * - Expired
     * - Revoked
     *
     * Commonly used in:
     * - API Gateways
     * - Security filters
     * - Internal service-to-service validation
     *
     * Headers:
     * - Authorization: Basic base64(clientId:clientSecret)
     *
     * Required form parameters:
     * - token=access_token
     *
     * Returns:
     * - Token metadata including:
     *   active, exp, sub, client_id, scope
     */
    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token/introspect",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> introspectToken(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, ?> formData
    );

    /**
     * 🚪 LOGOUT / SESSION TERMINATION
     *
     * Logs out the user from Keycloak by invalidating
     * the refresh token.
     *
     * Important:
     * - Access tokens are stateless and cannot be revoked
     * - Refresh tokens ARE invalidated
     *
     * Required form parameters:
     * - client_id
     * - client_secret
     * - refresh_token
     */
    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/logout",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    void logout(@RequestBody Map<String, ?> formData);

    /**
     * 🔄 TOKEN REFRESH
     *
     * Generates a new access token using a refresh token.
     *
     * Used when:
     * - access token is expired
     * - user session is still valid
     *
     * Required form parameters:
     * - grant_type=refresh_token
     * - client_id
     * - client_secret
     * - refresh_token
     *
     * Returns:
     * - New access_token
     * - New refresh_token
     */
    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> refreshToken(@RequestBody Map<String, ?> formData);
}
