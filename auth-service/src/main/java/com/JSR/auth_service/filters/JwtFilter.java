package com.JSR.auth_service.filters;

import com.JSR.auth_service.utils.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        // Skip processing if no Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        try {
            // Extract username from JWT token
            username = jwtUtil.extractEmail(jwt);

            // If username is valid and no authentication exists in context
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Validate token
                if (jwtUtil.isTokenValid(jwt)) {

                    // Option 1: Load full user details from database (includes roles)
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // Option 2: Extract roles directly from token (faster, no DB hit)
                     List<String> roles = jwtUtil.extractRoles(jwt);
                     List<SimpleGrantedAuthority> authorities = roles.stream()
                             .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                             .toList();

                    // Create authentication token
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    // Add request details
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Authenticated user: {}", username);
                } else {
                    log.warn("Invalid JWT token for user: {}", username);
                }
            }

        } catch (ExpiredJwtException e) {
            log.error("JWT token expired for user: {}", e.getClaims().getSubject());
            sendErrorResponse(response, "Token expired. Please login again.", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token format: {}", e.getMessage());
            sendErrorResponse(response, "Invalid token format.", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (SignatureException e) {
            log.error("JWT signature verification failed: {}", e.getMessage());
            sendErrorResponse(response, "Invalid token signature.", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (Exception e) {
            log.error("JWT validation error: {}", e.getMessage());
            sendErrorResponse(response, "Authentication failed.", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Skip JWT validation for public endpoints and login
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        String method = request.getMethod();

        // Skip JWT filter for these endpoints
        return path.startsWith("/api/v1/auth/**") ||           // All auth endpoints
                path.startsWith("/api/public/") ||         // Public endpoints
                path.startsWith("/oauth2/") ||             // OAuth2
                path.startsWith("/api/health") ||          // Health checks
                path.startsWith("/api/test/") ||           // Test endpoints
                path.startsWith("/api/files/") ||          // File endpoints
                path.startsWith("/check/") ||              // Check endpoints
                path.startsWith("/api/ollama/");           // Ollama endpoints
    }

    /**
     * Send standardized error response
     */
    private void sendErrorResponse(HttpServletResponse response, String message, int status) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(String.format("{\"error\": \"%s\", \"status\": %d}", message, status));
    }

    /**
     * Utility method to extract JWT token from request
     */
    public String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Get current authenticated username from SecurityContext
     */
    public String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof UserDetails) {
                return ((UserDetails) principal).getUsername();
            } else if (principal instanceof String) {
                return (String) principal;
            }
        }
        return null;
    }

    /**
     * Check if user has a specific role
     */
    public boolean hasRole(String role) {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            return SecurityContextHolder.getContext().getAuthentication()
                    .getAuthorities()
                    .stream()
                    .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role));
        }
        return false;
    }
}