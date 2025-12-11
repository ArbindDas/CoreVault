package com.JSR.auth_service.services;


import com.JSR.auth_service.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

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


    /**
     * Blacklist a single token
     */
    public void blacklistToken(String token){


        try {

            String username = jwtUtil.extractEmail(token);

            Long expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();

            if (expirationMs > 0){
                // Store token in blacklist with TTL matching  token expiration

                String blacklistKey = BLACKLIST_PREFIX + token;
                redisTemplate.opsForValue().set(
                        blacklistKey,
                        username,
                        expirationMs,
                        TimeUnit.MILLISECONDS
                );

                // remove from user's active tokens
                String userTokensKey = USER_TOKENS_PREFIX + username;
                redisTemplate.opsForSet().remove(userTokensKey, token);

                log.debug("Token blackList for user{} ", username);


            }

        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            throw new RuntimeException("Failed to blacklist token");
        }
    }


    /**
     * Blacklist all tokens for a user
     */

    public void blacklistAllUserTokens(String username){


        try {

            // Get all tokens for this user
            String userTokensKey = USER_TOKENS_PREFIX+username;
            Set<String>userTokens = redisTemplate.opsForSet().members(userTokensKey);


            if (userTokens != null && !userTokens.isEmpty()){
                // blacklist each token
                for (String token : userTokens){
                    blacklistToken(token);
                }
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
    public void storeActiveToken(String username, String token) {
        try {
            long expirationMs = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();

            // Add to user's active tokens set
            String userTokensKey = USER_TOKENS_PREFIX + username;
            redisTemplate.opsForSet().add(userTokensKey, token);
            redisTemplate.expire(userTokensKey, expirationMs, TimeUnit.MILLISECONDS);

            log.debug("Token stored for user: {}", username);
        } catch (Exception e) {
            log.error("Failed to store active token: {}", e.getMessage());
        }
    }

}
