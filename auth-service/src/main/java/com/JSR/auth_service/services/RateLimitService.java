package com.JSR.auth_service.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class RateLimitService {

    private final RedisTemplate<String, String> redisTemplate;

    @Autowired
    public RateLimitService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isRateLimited(String key, int maxRequests, Duration duration) {
        String redisKey = "ratelimit:" + key;

        Long current = redisTemplate.opsForValue().increment(redisKey);

        if (current == 1) {
            // First request - set expiration
            redisTemplate.expire(redisKey, duration.toSeconds(), TimeUnit.SECONDS);
        }

        if (current != null && current > maxRequests) {
            log.debug("Rate limit exceeded for key: {}", key);
            return true;
        }

        return false;
    }

    // Enhanced version with sliding window (more accurate)
    public boolean isRateLimitedSlidingWindow(String key, int maxRequests, Duration window) {
        String redisKey = "ratelimit:sw:" + key;
        long now = System.currentTimeMillis();
        long windowStart = now - window.toMillis();

        // Remove old entries
        redisTemplate.opsForZSet().removeRangeByScore(redisKey, 0, windowStart);

        // Count requests in window
        Long count = redisTemplate.opsForZSet().count(redisKey, windowStart, now);

        if (count != null && count >= maxRequests) {
            return true;
        }

        // Add current request
        redisTemplate.opsForZSet().add(redisKey, UUID.randomUUID().toString(), now);
        redisTemplate.expire(redisKey, window.toSeconds() + 1, TimeUnit.SECONDS);

        return false;
    }
}