//package com.JSR.user_management_service.controllers;
//
//import com.JSR.user_management_service.service.KeycloakAdminService;
//import com.JSR.user_management_service.service.impl.KeycloakAdminServiceImpl;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//import java.util.stream.Collectors;
//
//@RestController
//@RequestMapping("/api/debug")
//@Slf4j
//@RequiredArgsConstructor
//public class DebugController {
//
//
//    private final KeycloakAdminServiceImpl keycloakAdminService;
//
//    @GetMapping("/auth-info")
//    public ResponseEntity<?> getAuthInfo() {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Map<String, Object> response = new HashMap<>();
//
//        if (auth != null) {
//            response.put("authenticated", true);
//            response.put("name", auth.getName());
//            response.put("principalType", auth.getPrincipal().getClass().getName());
//
//            // Get authorities
//            List<String> authorities = auth.getAuthorities().stream()
//                    .map(GrantedAuthority::getAuthority)
//                    .collect(Collectors.toList());
//            response.put("authorities", authorities);
//
//            // Get JWT claims if available
//            if (auth.getPrincipal() instanceof Jwt) {
//                Jwt jwt = (Jwt) auth.getPrincipal();
//                response.put("subject", jwt.getSubject());
//                response.put("realm_access", jwt.getClaim("realm_access"));
//                response.put("rolesFromClaim", jwt.getClaimAsStringList("realm_access.roles"));
//            }
//
//            // Check if has ADMIN role
//            boolean hasAdminRole = authorities.stream()
//                    .anyMatch(authStr -> authStr.equals("ROLE_ADMIN"));
//            response.put("hasAdminRole", hasAdminRole);
//        } else {
//            response.put("authenticated", false);
//        }
//
//        return ResponseEntity.ok(response);
//    }
//
//
//    @GetMapping("/test-keycloak-connection")
//    public ResponseEntity<?> testKeycloakConnection() {
//        try {
//            // Try to get admin token
//            String token = keycloakAdminService.getAdminToken();
//
//            Map<String, Object> response = new HashMap<>();
//            response.put("success", true);
//            response.put("message", "Keycloak admin connection successful");
//            response.put("tokenPrefix", token.substring(0, Math.min(20, token.length())) + "...");
//
//            return ResponseEntity.ok(response);
//
//        } catch (Exception e) {
//            Map<String, Object> response = new HashMap<>();
//            response.put("success", false);
//            response.put("message", "Keycloak admin connection failed: " + e.getMessage());
//            response.put("error", e.getClass().getName());
//
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body(response);
//        }
//    }
//
//
//}


package com.JSR.user_management_service.controllers;

import com.JSR.user_management_service.service.KeycloakAdminService;
import com.JSR.user_management_service.service.impl.KeycloakAdminServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * DebugController provides endpoints to:
 * 1. Inspect authentication information of the current user
 * 2. Test connectivity with Keycloak admin API
 *
 * This controller is mainly useful for:
 * - Developers during debugging and testing
 * - Checking if JWT, roles, and permissions are correctly configured
 * - Ensuring that Keycloak connection works from the service
 */
@RestController
@RequestMapping("/api/debug") // Base URL for all debug endpoints
@Slf4j
@RequiredArgsConstructor
public class DebugController {

    // Service to communicate with Keycloak Admin API
    private final KeycloakAdminServiceImpl keycloakAdminService;

    /**
     * Endpoint: GET /api/debug/auth-info
     *
     * Purpose:
     * - Provides detailed information about the currently authenticated user
     * - Shows username, roles, and JWT claims
     * - Helps debug authentication and authorization issues
     *
     * @return JSON object with authentication details
     */
    @GetMapping("/auth-info")
    public ResponseEntity<?> getAuthInfo() {
        // Get current authentication object from Spring Security context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> response = new HashMap<>();

        if (auth != null) {
            // User is authenticated
            response.put("authenticated", true);
            response.put("name", auth.getName());
            response.put("principalType", auth.getPrincipal().getClass().getName());

            // Extract roles/authorities
            List<String> authorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            response.put("authorities", authorities);

            // Extract JWT claims if the principal is a Jwt
            if (auth.getPrincipal() instanceof Jwt) {
                Jwt jwt = (Jwt) auth.getPrincipal();
                response.put("subject", jwt.getSubject()); // User ID / subject from JWT
                response.put("realm_access", jwt.getClaim("realm_access")); // Full realm access claim
                response.put("rolesFromClaim", jwt.getClaimAsStringList("realm_access.roles")); // Roles extracted from claim
            }

            // Check if user has ADMIN role
            boolean hasAdminRole = authorities.stream()
                    .anyMatch(authStr -> authStr.equals("ROLE_ADMIN"));
            response.put("hasAdminRole", hasAdminRole);

        } else {
            // User is not authenticated
            response.put("authenticated", false);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint: GET /api/debug/test-keycloak-connection
     *
     * Purpose:
     * - Tests if the service can connect to Keycloak Admin API
     * - Generates an admin token to ensure credentials and server are working
     * - Useful for debugging Keycloak connectivity issues
     *
     * @return JSON indicating success/failure and part of the admin token
     */
    @GetMapping("/test-keycloak-connection")
    public ResponseEntity<?> testKeycloakConnection() {
        try {
            // Attempt to get admin token from Keycloak
            String token = keycloakAdminService.getAdminToken();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Keycloak admin connection successful");
            // Show only first 20 characters of token for security
            response.put("tokenPrefix", token.substring(0, Math.min(20, token.length())) + "...");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // Handle failure to connect or get token
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Keycloak admin connection failed: " + e.getMessage());
            response.put("error", e.getClass().getName());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(response);
        }
    }
}
