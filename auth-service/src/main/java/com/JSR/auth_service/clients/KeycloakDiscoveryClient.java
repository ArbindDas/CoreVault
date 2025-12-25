package com.JSR.auth_service.clients;

import com.JSR.auth_service.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@FeignClient(
        name = "keycloak-discovery-client",
        url = "${keycloak.auth-server-url}",
        configuration = FeignConfig.class
)
public interface KeycloakDiscoveryClient {

    @GetMapping("/realms/${keycloak.realm}/.well-known/openid-configuration")
    Map<String, Object> getConfiguration();
}