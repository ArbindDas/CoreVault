

package com.JSR.user_management_service.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Map;

@FeignClient(
        name = "keycloak-token-client",
        url = "http://keycloak:8080",  // ✅ Hardcoded URL
        configuration = com.JSR.user_management_service.config.FeignConfig.class
)
public interface TokenClient {

    @PostMapping(
            value = "/realms/{realm}/protocol/openid-connect/token",  // ✅ Use path variable
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getAdminToken(
            @PathVariable("realm") String realm,  // ✅ Add realm parameter
            MultiValueMap<String, String> formData
    );

    @PostMapping(
            value = "/realms/master/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    Map<String, Object> getMasterRealmToken(MultiValueMap<String, String> formData);
}