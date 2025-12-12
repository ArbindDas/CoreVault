package com.JSR.auth_service.services;


import com.JSR.auth_service.utils.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class TokenBlacklistService {


    private final RedisTemplate<String , String> redisTemplate;
    private final JwtUtil jwtUtil;





    @Autowired
    public TokenBlacklistService(RedisTemplate<String, String> redisTemplate, JwtUtil jwtUtil) {
        this.redisTemplate = redisTemplate;
        this.jwtUtil = jwtUtil;
    }


    private static final String BLACKLIST_PREFIX = "blacklist:token";
    private static final String USER_TOKENS_PREFIX= "user:tokens";
    private static final String ALL_USERS_KEY = "users:all"; // Optional: to track all users


    /**
     * Blacklist a single token
     */
//    public void blacklistToken(String token){
//        try {
//            String username = jwtUtil.extractEmail(token);
//            Long expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();
//            if (expirationMs > 0){
//                // Store token in blacklist with TTL matching  token expiration
//                String blacklistKey = BLACKLIST_PREFIX + token;
//                redisTemplate.opsForValue().set(
//                        blacklistKey,
//                        username,
//                        expirationMs,
//                        TimeUnit.MILLISECONDS
//                );
//                // remove from user's active tokens
//                String userTokensKey = USER_TOKENS_PREFIX + username;
//                redisTemplate.opsForSet().remove(userTokensKey, token);
//
//                log.debug("Token blackList for user{} ", username);
//            }
//
//        } catch (Exception e) {
//            log.error("Failed to blacklist token: {}", e.getMessage());
//            throw new RuntimeException("Failed to blacklist token");
//        }
//    }


    /**
     * Blacklist all tokens for a user
     */

    public void blacklistAllUserTokens(String username){


        try {


            log.info("🔄 Starting logout from ALL devices for user: {}", username);

            // Get all tokens for this user
            String userTokensKey = USER_TOKENS_PREFIX+username;
            Set<String>userTokens = redisTemplate.opsForSet().members(userTokensKey);


            int count = 0;
            // blacklist each token
            if (userTokens != null && !userTokens.isEmpty()){
                // blacklist each token

                for (String token : userTokens){
                    blacklistToken(token);
                    count++;
                    if (count % 10 == 0) {
                        log.debug("Processed {} tokens...", count);
                    }
                }
                log.info("✅ Successfully blacklisted {} tokens", count);
            }else {
                log.info("ℹ️ No active tokens found for user: {}", username);
            }

            // clear user's token set
            redisTemplate.delete(userTokensKey);
            log.info("All tokens blacklisted for user: {}", username);

        } catch (Exception e) {
            log.error("Failed to blacklist all tokens for user {}: {}", username, e.getMessage());
            throw new RuntimeException("Failed to logout from all devices");
        }

    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token){
        String blacklistkey = BLACKLIST_PREFIX+token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistkey));
    }

    /**
     * Store active token for user (call this during login)
     */
//    public void storeActiveToken(String username, String token) {
//        try {
//            long expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();
//
//            // Add to user's active tokens set
//            String userTokensKey = USER_TOKENS_PREFIX + username;
//            redisTemplate.opsForSet().add(userTokensKey, token);
//            redisTemplate.expire(userTokensKey, expirationMs, TimeUnit.MILLISECONDS);
//
//            log.debug("Token stored for user: {}", username);
//        } catch (Exception e) {
//            log.error("Failed to store active token: {}", e.getMessage());
//        }
//    }


    /**
     * Clean up expired tokens from a specific user's token set
     */
    public void cleanupExpiredTokensFromSet(String username) {
        try {
            String userTokensKey = USER_TOKENS_PREFIX + username;
            Set<String> tokens = redisTemplate.opsForSet().members(userTokensKey);

            if (tokens == null || tokens.isEmpty()) {
                log.debug("No tokens to clean up for user: {}", username);
                return;
            }

            log.info("🔄 Starting token cleanup for user: {} ({} tokens found)", username, tokens.size());

            List<String> toRemove = new ArrayList<>();
            int expiredCount = 0;
            int invalidCount = 0;

            for (String token : tokens) {
                try {
                    if (jwtUtil.isTokenExpired(token)) {
                        toRemove.add(token);
                        expiredCount++;
                        log.debug("Found expired token ending with: ...{}",
                                token.substring(Math.max(0, token.length() - 10)));
                    }
                } catch (ExpiredJwtException e) {
                    // Already expired - remove it
                    toRemove.add(token);
                    expiredCount++;
                    log.debug("Found expired JWT for user: {}", username);
                } catch (Exception e) {
                    // Completely invalid token - remove it
                    toRemove.add(token);
                    invalidCount++;
                    log.warn("Found invalid/unparseable token for user: {}", username);
                }
            }

            if (!toRemove.isEmpty()) {
                // Remove expired/invalid tokens from the set
                Long removed = redisTemplate.opsForSet().remove(userTokensKey, (Object) toRemove.toArray(new String[0]));

                // Also clean up from blacklist if they're there
                for (String token : toRemove) {
                    String blacklistKey = BLACKLIST_PREFIX + token;
                    redisTemplate.delete(blacklistKey);
                }

                log.info("✅ Cleaned up {}/{} tokens for user {} ({} expired, {} invalid)",
                        removed, toRemove.size(), username, expiredCount, invalidCount);

                // If set is now empty, delete it to save space
                Long remaining = redisTemplate.opsForSet().size(userTokensKey);
                if (remaining != null && remaining == 0) {
                    redisTemplate.delete(userTokensKey);
                    log.debug("Deleted empty token set for user: {}", username);
                }
            } else {
                log.info("✅ No expired/invalid tokens found for user: {}", username);
            }

        } catch (Exception e) {
            log.error("❌ Failed to cleanup expired tokens for user {}: {}", username, e.getMessage());
            // Don't throw - cleanup failures shouldn't break the app
        }
    }

    /**
     * Clean up ALL expired tokens from ALL users
     * Call this periodically (e.g., every hour)
     */
    @Scheduled(fixedDelay = 3600000) // 1 hour = 3600000 milliseconds
    public void scheduledCleanupAllUsers() {
        try {
            log.info("🕐 Starting scheduled token cleanup for ALL users...");

            // Find all user token keys
            Set<String> allUserKeys = redisTemplate.keys(USER_TOKENS_PREFIX + "*");

            if (allUserKeys == null || allUserKeys.isEmpty()) {
                log.info("ℹ️ No user token sets found for cleanup");
                return;
            }

            log.info("Found {} user token sets to check", allUserKeys.size());
            int totalCleaned = 0;
            int processedUsers = 0;

            for (String userKey : allUserKeys) {
                try {
                    // Extract username from key
                    String username = userKey.substring(USER_TOKENS_PREFIX.length());

                    // Clean up this user's tokens
                    int beforeCount = redisTemplate.opsForSet().size(userKey) != null ?
                            redisTemplate.opsForSet().size(userKey).intValue() : 0;

                    cleanupExpiredTokensFromSet(username);

                    int afterCount = redisTemplate.opsForSet().size(userKey) != null ?
                            redisTemplate.opsForSet().size(userKey).intValue() : 0;

                    int cleaned = beforeCount - afterCount;
                    totalCleaned += cleaned;

                    processedUsers++;
                    if (processedUsers % 10 == 0) {
                        log.info("Processed {} users, cleaned {} tokens so far...",
                                processedUsers, totalCleaned);
                    }

                } catch (Exception e) {
                    log.warn("Failed to cleanup tokens for key {}: {}", userKey, e.getMessage());
                }
            }

            log.info("✅ Scheduled cleanup completed: Processed {} users, removed {} expired/invalid tokens",
                    processedUsers, totalCleaned);

        } catch (Exception e) {
            log.error("❌ Scheduled cleanup failed: {}", e.getMessage(), e);
        }
    }


    /**
     * Clean up expired blacklisted tokens (they auto-expire but this ensures cleanup)
     */
    @Scheduled(fixedDelay = 7200000) // Every 2 hours
    public void cleanupExpiredBlacklistedTokens() {
        try {
            // Note: Blacklisted tokens already have TTL and auto-expire
            // This is just extra safety to clean up any that might have stuck around
            log.debug("Checking for expired blacklisted tokens...");
            // Redis automatically removes expired keys, so this is mostly for logging
        } catch (Exception e) {
            log.error("Failed to cleanup blacklisted tokens: {}", e.getMessage());
        }
    }

    /**
     * Enhanced storeActiveToken with automatic cleanup before adding
     */
    public void storeActiveToken(String username, String token) {
        try {
            // Clean up expired tokens before adding new one
            cleanupExpiredTokensFromSet(username);

            long expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();

            if (expirationMs <= 0) {
                log.warn("Token already expired, not storing for user: {}", username);
                return;
            }

            // Add to user's active tokens set
            String userTokensKey = USER_TOKENS_PREFIX + username;
            redisTemplate.opsForSet().add(userTokensKey, token);
            redisTemplate.expire(userTokensKey, expirationMs, TimeUnit.MILLISECONDS);

            log.info("✅ Token stored for user: {} (expires in {} minutes)",
                    username, expirationMs / 60000);

        } catch (Exception e) {
            log.error("❌ Failed to store active token for user {}: {}", username, e.getMessage());
            // Don't throw - we don't want login to fail if token storage has issues
        }
    }


    /**
     * Enhanced blacklistToken method that handles expired tokens
     */
    public void blacklistToken(String token) {
        try {
            String username;
            Long expirationMs;

            try {
                // Try to extract info from token
                username = jwtUtil.extractEmail(token);
                expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();
            } catch (ExpiredJwtException e) {
                // Handle expired tokens
                username = e.getClaims().getSubject();
                expirationMs = 0L;
                log.debug("Processing expired token for user: {}", username);
            } catch (Exception e) {
                log.warn("Skipping invalid token during blacklist: {}", e.getMessage());
                return;
            }

            if (expirationMs > 0) {
                // Valid token - blacklist with its remaining TTL
                String blacklistKey = BLACKLIST_PREFIX + token;
                redisTemplate.opsForValue().set(
                        blacklistKey,
                        username,
                        expirationMs,
                        TimeUnit.MILLISECONDS
                );
                log.debug("Token blacklisted for {} (TTL: {}ms)", username, expirationMs);
            } else {
                // Expired token - blacklist with short TTL
                String blacklistKey = BLACKLIST_PREFIX + token;
                redisTemplate.opsForValue().set(
                        blacklistKey,
                        username,
                        300, // 5 minutes
                        TimeUnit.SECONDS
                );
                log.debug("Expired token blacklisted for {} (short TTL)", username);
            }

            // Remove from user's active tokens
            String userTokensKey = USER_TOKENS_PREFIX + username;
            redisTemplate.opsForSet().remove(userTokensKey, token);

        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            throw new RuntimeException("Failed to blacklist token");
        }
    }

}
