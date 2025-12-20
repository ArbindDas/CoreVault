package com.JSR.auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Auth-service endpoints are ALL PUBLIC
                // No authentication required because:
                // 1. Signup doesn't need auth
                // 2. Token validation validates externally
                // 3. Password reset doesn't need auth
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()  // ALL endpoints are public
                );

        // ❌ NO oauth2ResourceServer() configuration!
        // ❌ NO jwtDecoder() bean!

        return http.build();
    }
}