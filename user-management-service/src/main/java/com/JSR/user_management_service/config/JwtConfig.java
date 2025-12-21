package com.JSR.user_management_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;

import java.util.Arrays;
import java.util.List;

@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(
                "http://keycloak:8080/realms/microservices-realm/protocol/openid-connect/certs"
        ).build();

        // Custom validator that accepts multiple issuers
        OAuth2TokenValidator<Jwt> issuerValidator = new OAuth2TokenValidator<Jwt>() {
            private final List<String> validIssuers = Arrays.asList(
                    "http://localhost:8080/realms/microservices-realm",
                    "http://keycloak:8080/realms/microservices-realm"
            );

            @Override
            public OAuth2TokenValidatorResult validate(Jwt token) {
                String issuer = token.getIssuer().toString();
                if (validIssuers.contains(issuer)) {
                    return OAuth2TokenValidatorResult.success();
                }
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Invalid issuer: " + issuer, null)
                );
            }
        };

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                issuerValidator
        ));

        return jwtDecoder;
    }
}