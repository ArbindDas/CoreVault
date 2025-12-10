package com.JSR.auth_service.config;


import com.JSR.auth_service.filters.JwtFilter;
import com.JSR.auth_service.filters.JwtValidationFilter;
import com.JSR.auth_service.services.CustomUserDetailsService;
import jakarta.servlet.Filter;
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
    private final JwtValidationFilter jwtValidationFilter;

    @Autowired
    public SpringSecurity(
            CustomUserDetailsService userDetailsService,
            JwtAuthEntryPoint authEntryPoint,
            JwtFilter jwtFilter,
            JwtValidationFilter jwtValidationFilter

    ) {
        this.userDetailsService = userDetailsService;
        this.authEntryPoint = authEntryPoint;
        this.jwtFilter = jwtFilter;
        this.jwtValidationFilter = jwtValidationFilter;
    }



    @Bean
    public SecurityFilterChain securityFilterChain( HttpSecurity http ) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(expection -> expection
                        .authenticationEntryPoint(authEntryPoint)
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/test",
                                "/api/auth/signin"
                        ).permitAll()
                        .anyRequest().authenticated()


                )
                 // ✅ DISABLE CSRF completely for stateless JWT APIs
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore((Filter) jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtValidationFilter , JwtValidationFilter.class);


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
