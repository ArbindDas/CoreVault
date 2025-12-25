package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@FeignClient(
        name = "keycloak-token-client",
        url = "${keycloak.auth-server-url}",
        configuration = FeignConfig.class
)
public interface KeycloakTokenClient {

    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getToken(@RequestBody Map<String, ?> formData);

    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token/introspect",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> introspectToken(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, ?> formData
    );

    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/logout",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    void logout(@RequestBody Map<String, ?> formData);

    @PostMapping(
            value = "/realms/${keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> refreshToken(@RequestBody Map<String, ?> formData);
}