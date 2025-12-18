package com.JSR.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

@Configuration
public class JwtConfig {

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {  // ⬅️ MUST be ReactiveJwtDecoder!
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(
                "http://keycloak:8080/realms/microservices-realm/protocol/openid-connect/certs"
        ).build();

        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(
                "http://localhost:8080/realms/microservices-realm"
        );

        // For ReactiveJwtDecoder, you need to wrap the validator
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                issuerValidator
        ));

        return jwtDecoder;
    }
}