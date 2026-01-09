//
//
//package com.JSR.user_management_service.clients;
//
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.http.MediaType;
//import org.springframework.util.MultiValueMap;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.PostMapping;
//
//import java.util.Map;
//
//@FeignClient(
//        name = "keycloak-token-client",
//        url = "http://keycloak:8080",  // ✅ Hardcoded URL
//        configuration = com.JSR.user_management_service.config.FeignConfig.class
//)
//public interface TokenClient {
//
//    @PostMapping(
//            value = "/realms/{realm}/protocol/openid-connect/token",  // ✅ Use path variable
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    Map<String, Object> getAdminToken(
//            @PathVariable("realm") String realm,  // ✅ Add realm parameter
//            MultiValueMap<String, String> formData
//    );
//
//    @PostMapping(
//            value = "/realms/master/protocol/openid-connect/token",
//            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
//    )
//    Map<String, Object> getMasterRealmToken(MultiValueMap<String, String> formData);
//}


package com.JSR.user_management_service.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import java.util.Map;

/**
 * TokenClient is a Feign client for communicating with Keycloak's
 * OpenID Connect token endpoints.
 *
 * This client is used for:
 * 1. Obtaining admin tokens for a specific realm
 * 2. Obtaining tokens from the master realm (usually for admin operations)
 *
 * Important notes:
 * - URL is hardcoded to "http://keycloak:8080" because it's assumed
 *   that Keycloak is running in Docker and this is the container hostname.
 * - MultiValueMap is used to send form-data parameters like grant_type,
 *   client_id, client_secret, username, and password.
 */
@FeignClient(
        name = "keycloak-token-client",
        url = "http://keycloak:8080",  // ✅ Base URL for Keycloak server inside Docker
        configuration = com.JSR.user_management_service.config.FeignConfig.class
)
public interface TokenClient {

    /**
     * Get an admin token for a specific realm.
     *
     * Purpose:
     * - Called when the microservice needs to interact with Keycloak Admin API.
     * - Retrieves an access token that allows privileged operations like creating users,
     *   updating users, or fetching realm users.
     *
     * @param realm The Keycloak realm for which to get the admin token (e.g., "microservices-realm")
     * @param formData Form parameters for token request (grant_type, client_id, client_secret, username, password)
     * @return A map containing access_token, refresh_token, token_type, expires_in, etc.
     */
    @PostMapping(
            value = "/realms/{realm}/protocol/openid-connect/token",  // Token endpoint for a specific realm
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getAdminToken(
            @PathVariable("realm") String realm,  // Realm path variable
            MultiValueMap<String, String> formData // Form parameters for token request
    );

    /**
     * Get a token from the master realm.
     *
     * Purpose:
     * - Usually used to authenticate as a Keycloak admin user to perform
     *   high-level administrative operations (e.g., create users in other realms)
     *
     * @param formData Form parameters for master realm token request (grant_type, client_id, client_secret, username, password)
     * @return A map containing access_token, refresh_token, token_type, expires_in, etc.
     */
    @PostMapping(
            value = "/realms/master/protocol/openid-connect/token", // Token endpoint for master realm
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getMasterRealmToken(MultiValueMap<String, String> formData);
}
