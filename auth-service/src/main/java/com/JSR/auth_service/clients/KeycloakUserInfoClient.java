//package com.JSR.auth_service.clients;
//
//import com.JSR.auth_service.config.FeignConfig;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestHeader;
//
//import java.util.Map;
//
//@FeignClient(
//        name = "keycloak-userinfo-client",
//        url = "${keycloak.auth-server-url}",
//        configuration = FeignConfig.class
//)
//public interface KeycloakUserInfoClient {
//
//    @GetMapping("/realms/${keycloak.realm}/protocol/openid-connect/userinfo")
//    Map<String, Object> getUserInfo(@RequestHeader("Authorization") String authorization);
//}




package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

/**
 * Feign client responsible for retrieving authenticated user information
 * from Keycloak using the OpenID Connect UserInfo endpoint.
 *
 * Purpose:
 * - Fetch identity details of the currently authenticated user
 * - Validate that an access token belongs to a real user
 * - Retrieve profile information after successful login
 *
 * This client does NOT:
 * - Authenticate users
 * - Issue tokens
 * - Register users
 *
 * It only works with a VALID access token.
 */
@FeignClient(
        // Logical name of the Feign client
        name = "keycloak-userinfo-client",

        // Base URL of the Keycloak server
        url = "${keycloak.auth-server-url}",

        // Custom Feign configuration (timeouts, logging, encoders)
        configuration = FeignConfig.class
)
public interface KeycloakUserInfoClient {

    /**
     * 👤 FETCH USER INFORMATION
     *
     * Calls Keycloak's UserInfo endpoint defined by OpenID Connect.
     *
     * Endpoint:
     *   /realms/{realm}/protocol/openid-connect/userinfo
     *
     * Authorization:
     * - Requires a valid Bearer access token
     *
     * Header example:
     *   Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6...
     *
     * Returns:
     * - A map containing user identity claims such as:
     *   - sub (unique user identifier)
     *   - preferred_username
     *   - email
     *   - given_name
     *   - family_name
     *
     * Common use cases:
     * - Build `/me` or `/profile` API
     * - Sync Keycloak user with local database
     * - Verify token-to-user mapping
     */
    @GetMapping("/realms/${keycloak.realm}/protocol/openid-connect/userinfo")
    Map<String, Object> getUserInfo(
            @RequestHeader("Authorization") String authorization
    );
}
