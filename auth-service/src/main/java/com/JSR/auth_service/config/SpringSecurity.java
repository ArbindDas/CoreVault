package com.JSR.auth_service.config;


import com.JSR.auth_service.filters.JwtFilter;
import com.JSR.auth_service.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;


@Configuration
public class SpringSecurity {

    private final JwtAuthEntryPoint authEntryPoint;
    private final CustomUserDetailsService userDetailsService;
    private final JwtFilter jwtFilter;


    @Autowired
    public SpringSecurity(
            CustomUserDetailsService userDetailsService,
            JwtAuthEntryPoint authEntryPoint,
            JwtFilter jwtFilter


    ) {
        this.userDetailsService = userDetailsService;
        this.authEntryPoint = authEntryPoint;
        this.jwtFilter = jwtFilter;
    }



    @Bean
    public SecurityFilterChain securityFilterChain( HttpSecurity http ) throws Exception {
        http
                // 1️⃣ CORS Configuration - Allows cross-origin requests
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 2️⃣ Exception Handling - What happens when auth fails
                .exceptionHandling(expection -> expection // Returns 401 for unauthorized
                        .authenticationEntryPoint(authEntryPoint)
                )

                // 3️⃣ Session Management - Critical for JWT!
                .sessionManagement(session -> session // no http sessions
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 4️⃣ Authorization Rules - Who can access what
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (no auth required)
                        .requestMatchers(
                                "/api/test",
                                "/api/v1/auth/**",
                                "/api/test",
                                "/api/health",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/swagger-resources/**",
                                "/webjars/**"
                        ).permitAll()



                        // Role-based access (Note: hasRole() auto-adds "ROLE_" prefix)
                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // 👉 Expects "ROLE_ADMIN" in token

                        // Authenticated endpoints (any logged-in user)
                        .requestMatchers("/api/users/getAllUsers").authenticated()

                        // Final rule: everything else needs authentication
                        .anyRequest().authenticated()


                )
                 // ✅ DISABLE CSRF completely for stateless JWT APIs
                .csrf(AbstractHttpConfigurer::disable)

                // 6️⃣ 🔥 FILTER CHAIN - Where the magic happens
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();

    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity)throws Exception{
        AuthenticationManagerBuilder authBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        return authBuilder.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(Arrays.asList(
                "http://localhost:5173",
                "http://127.0.0.1:5173"
        ));

        // Allowed methods (include PUT for direct S3 uploads if needed)
        config.setAllowedMethods(Arrays.asList(
                "GET", "POST", "DELETE", "OPTIONS", "HEAD"
        ));

        //Allowed headers (add s3-specific headers)
        config.setAllowedHeaders(Arrays.asList(
                "*",
                "Authorization",
                "Content-Type",
                "Content-Disposition",
                "x-amz-acl",
                "x-amz-meta-*"
        ));

        config.setAllowCredentials(true);
        config.addExposedHeader("Authorization");

        // Exposed headers (add S3-specific headers)

        config.setExposedHeaders(Arrays.asList(
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Embedder-Policy",
                "ETag",  // Important for S3
                "x-amz-version-id",
                "x-amz-request-id"
        ));


        config.setMaxAge(3600L); // Cache preflight requests for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;

    }
}
