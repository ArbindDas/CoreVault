//package com.JSR.user_service.utils;
//
//
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.stereotype.Component;
//
//@Component
//public class JwtUtil {
//
//    public String getUserId(){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt)  {
//            Jwt jwt = (Jwt) authentication.getPrincipal();
//            return jwt.getSubject(); // Keycloak User ID
//        }
//        return null;
//    }
//
//
//    public String getEmail(){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
//
//            Jwt jwt = (Jwt) authentication.getPrincipal();
//            return jwt.getClaim("email");
//        }
//        return null;
//    }
//
//    public String getUsername(){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
//
//            Jwt jwt = (Jwt) authentication.getPrincipal();
//
//            return jwt.getClaim("preferred_username");
//        }
//
//        return null;
//    }
//}


package com.JSR.user_service.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtUtil {

    public String getUserId() {
        log.debug("=== JwtUtil.getUserId() called ===");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logAuthenticationDetails(authentication);

        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String userId = jwt.getSubject();
            log.info("✅ Extracted User ID from JWT: {}", userId);
            log.debug("JWT Claims: {}", jwt.getClaims());
            return userId;
        }

        log.warn("⚠️ No JWT token found or authentication is null");
        return null;
    }

    public String getEmail() {
        log.debug("=== JwtUtil.getEmail() called ===");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logAuthenticationDetails(authentication);

        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String email = jwt.getClaim("email");
            log.info("✅ Extracted email from JWT: {}", email);
            return email;
        }

        log.warn("⚠️ Cannot extract email - no JWT token found");
        return null;
    }

    public String getUsername() {
        log.debug("=== JwtUtil.getUsername() called ===");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logAuthenticationDetails(authentication);

        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String username = jwt.getClaim("preferred_username");
            log.info("✅ Extracted username from JWT: {}", username);
            return username;
        }

        log.warn("⚠️ Cannot extract username - no JWT token found");
        return null;
    }

    private void logAuthenticationDetails(Authentication authentication) {
        if (authentication == null) {
            log.error("❌ Authentication object is NULL");
            log.debug("SecurityContext: {}", SecurityContextHolder.getContext());
            return;
        }

        log.debug("Authentication Details:");
        log.debug("- Name: {}", authentication.getName());
        log.debug("- Principal Class: {}",
                authentication.getPrincipal() != null ?
                        authentication.getPrincipal().getClass().getName() : "null");
        log.debug("- Authorities: {}", authentication.getAuthorities());
        log.debug("- Is Authenticated: {}", authentication.isAuthenticated());
        log.debug("- Credentials: {}", authentication.getCredentials());

        // Log principal details
        Object principal = authentication.getPrincipal();
        if (principal instanceof String) {
            log.debug("- Principal (String): {}", principal);
        } else if (principal instanceof Jwt) {
            Jwt jwt = (Jwt) principal;
            log.debug("- JWT Subject: {}", jwt.getSubject());
            log.debug("- JWT Issuer: {}", jwt.getIssuer());
            log.debug("- JWT Expires At: {}", jwt.getExpiresAt());
        } else if (principal != null) {
            log.debug("- Principal Type: {}", principal.getClass().getName());
            log.debug("- Principal toString: {}", principal.toString());
        }
    }

    // Helper method to log full JWT details
    public void logFullJwtDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            log.info("=== FULL JWT DETAILS ===");
            log.info("Subject (User ID): {}", jwt.getSubject());
            log.info("Issuer: {}", jwt.getIssuer());
            log.info("Issued At: {}", jwt.getIssuedAt());
            log.info("Expires At: {}", jwt.getExpiresAt());
            log.info("All Claims:");
            jwt.getClaims().forEach((key, value) ->
                    log.info("  {}: {}", key, value)
            );
            log.info("=== END JWT DETAILS ===");
        } else {
            log.warn("No JWT available for full details logging");
        }
    }
}