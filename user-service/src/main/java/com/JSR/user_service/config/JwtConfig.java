
package com.JSR.user_service.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(
                "http://keycloak:8080/realms/microservices-realm/protocol/openid-connect/certs"
        ).build();

        // Accept ONLY what Keycloak actually issues
        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(
                "http://localhost:8080/realms/microservices-realm"
        );

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                issuerValidator
        ));
        return jwtDecoder;
    }

}