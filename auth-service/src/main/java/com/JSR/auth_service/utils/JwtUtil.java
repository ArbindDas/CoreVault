
package com.JSR.auth_service.utils;
import com.JSR.auth_service.entities.Roles;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private static final long EXPIRATION = 1000 * 60 * 60; // 1 hour

    @Value("${AUTH_SECRET_KEY}")
    private String secret;

    private SecretKey key;

    @PostConstruct
    public void init() {
        if (secret == null || secret.length() < 32) {
            throw new IllegalArgumentException("Secret key must be at least 32 characters long");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // Generate token with email and Set<Roles>
    public String generateToken(String email, Set<Roles> roles) {
        // Extract role names from Roles entities
        Set<String> roleNames = roles.stream()
                .map(Roles::getName)  // Assuming Roles has getName() method
                .collect(Collectors.toSet());

        return Jwts.builder()
                .subject(email)
                .claim("roles", new ArrayList<>(roleNames))  // Store as List<String>
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }


    // Extract email from token
    public String extractEmail(String token) {
        try {
            return getClaims(token).getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }

    // Extract roles from token - returns List<String>
//  todo->  When a user makes a request with a JWT, the backend needs to verify what roles the user has to control access.
//  todo->  This method allows you to read roles directly from the token without hitting the database every time.
//  todo->  Used in authorization checks, e.g., ROLE_ADMIN can access /admin endpoints, ROLE_USER cannot.

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        try {
            Claims claims = getClaims(token);
            Object rolesClaim = claims.get("roles");

            if (rolesClaim instanceof List) {
                return (List<String>) rolesClaim;
            }
            return Collections.emptyList();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token or no roles claim", e);
        }
    }

    // Extract roles as Set<String>
    public Set<String> extractRolesAsSet(String token) {
        return new HashSet<>(extractRoles(token));
    }

    // Validate token
    public boolean isTokenValid(String token, String email) {
        try {
            String extractedEmail = extractEmail(token);
            return extractedEmail.equals(email) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // Check token expiration
    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    // Parse claims (for jjwt 0.12.5)
    private Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    // Additional utility methods:

    // Validate token without email
    public boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // Get expiration date
    public Date getExpirationDate(String token) {
        return getClaims(token).getExpiration();
    }

    // Get issued at date
    public Date getIssuedAt(String token) {
        return getClaims(token).getIssuedAt();
    }
}