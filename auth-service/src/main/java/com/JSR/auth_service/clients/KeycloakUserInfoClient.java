package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@FeignClient(
        name = "keycloak-userinfo-client",
        url = "${keycloak.auth-server-url}",
        configuration = FeignConfig.class
)
public interface KeycloakUserInfoClient {

    @GetMapping("/realms/${keycloak.realm}/protocol/openid-connect/userinfo")
    Map<String, Object> getUserInfo(@RequestHeader("Authorization") String authorization);
}