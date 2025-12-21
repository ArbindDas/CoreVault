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

@RestController
@RequestMapping("/api/debug")
@Slf4j
@RequiredArgsConstructor
public class DebugController {


    private final KeycloakAdminServiceImpl keycloakAdminService;

    @GetMapping("/auth-info")
    public ResponseEntity<?> getAuthInfo() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> response = new HashMap<>();

        if (auth != null) {
            response.put("authenticated", true);
            response.put("name", auth.getName());
            response.put("principalType", auth.getPrincipal().getClass().getName());

            // Get authorities
            List<String> authorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            response.put("authorities", authorities);

            // Get JWT claims if available
            if (auth.getPrincipal() instanceof Jwt) {
                Jwt jwt = (Jwt) auth.getPrincipal();
                response.put("subject", jwt.getSubject());
                response.put("realm_access", jwt.getClaim("realm_access"));
                response.put("rolesFromClaim", jwt.getClaimAsStringList("realm_access.roles"));
            }

            // Check if has ADMIN role
            boolean hasAdminRole = authorities.stream()
                    .anyMatch(authStr -> authStr.equals("ROLE_ADMIN"));
            response.put("hasAdminRole", hasAdminRole);
        } else {
            response.put("authenticated", false);
        }

        return ResponseEntity.ok(response);
    }


    @GetMapping("/test-keycloak-connection")
    public ResponseEntity<?> testKeycloakConnection() {
        try {
            // Try to get admin token
            String token = keycloakAdminService.getAdminToken();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Keycloak admin connection successful");
            response.put("tokenPrefix", token.substring(0, Math.min(20, token.length())) + "...");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Keycloak admin connection failed: " + e.getMessage());
            response.put("error", e.getClass().getName());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(response);
        }
    }


}