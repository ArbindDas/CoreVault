//package com.JSR.auth_service.clients;
//
//import com.JSR.auth_service.config.FeignConfig;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.web.bind.annotation.GetMapping;
//
//import java.util.Map;
//
//@FeignClient(
//        name = "keycloak-discovery-client",
//        url = "${keycloak.auth-server-url}",
//        configuration = FeignConfig.class
//)
//public interface KeycloakDiscoveryClient {
//
//    @GetMapping("/realms/${keycloak.realm}/.well-known/openid-configuration")
//    Map<String, Object> getConfiguration();
//}

package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

/**
 * Feign client responsible for discovering Keycloak OpenID Connect (OIDC)
 * configuration dynamically.
 *
 * This client calls Keycloak's standard OIDC discovery endpoint:
 *
 *   /realms/{realm}/.well-known/openid-configuration
 *
 * Purpose:
 * - Avoid hardcoding Keycloak endpoints (token, jwks, auth, userinfo, etc.)
 * - Dynamically fetch OAuth2/OIDC metadata at runtime
 * - Improve maintainability and cloud readiness
 *
 * Common use cases:
 * - Fetch JWKS URI for JWT validation
 * - Discover token endpoint for authentication
 * - Validate issuer dynamically
 */
@FeignClient(
        // Logical name of this Feign client
        name = "keycloak-discovery-client",

        // Base URL of Keycloak server (e.g. http://localhost:8080)
        url = "${keycloak.auth-server-url}",

        // Custom Feign configuration (timeouts, logging, interceptors)
        configuration = FeignConfig.class
)
public interface KeycloakDiscoveryClient {

    /**
     * Calls Keycloak's OpenID Connect discovery endpoint.
     *
     * Endpoint:
     *   /realms/{realm}/.well-known/openid-configuration
     *
     * Returns:
     * - A map containing Keycloak OIDC metadata such as:
     *   - issuer
     *   - authorization_endpoint
     *   - token_endpoint
     *   - userinfo_endpoint
     *   - jwks_uri
     *   - supported scopes & grant types
     *
     * Why Map<String, Object>?
     * - Flexible structure
     * - Allows dynamic extraction of required fields
     *
     * Example usage:
     *   Map<String, Object> config = getConfiguration();
     *   String jwksUri = config.get("jwks_uri").toString();
     */
    @GetMapping("/realms/${keycloak.realm}/.well-known/openid-configuration")
    Map<String, Object> getConfiguration();
}
