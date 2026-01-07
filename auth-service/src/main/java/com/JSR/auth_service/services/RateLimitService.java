package com.JSR.auth_service.services;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

@Service
@Slf4j
public class RateLimitService {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    public Bucket resolveBucket(String key, String endpoint) {
        return cache.computeIfAbsent(key + ":" + endpoint, k -> createBucket(endpoint));
    }

    private Bucket createBucket(String endpoint) {
        Bandwidth limit;

        switch (endpoint) {
            case "signup":
                limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofHours(1)));
                break;
            case "login":
                limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1)));
                break;
            case "forgot-password":
                limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofHours(1)));
                break;
            case "resend-verification":
                limit = Bandwidth.classic(2, Refill.intervally(2, Duration.ofHours(1)));
                break;
            default:
                limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        }

        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    public void clearBucket(String key, String endpoint) {
        cache.remove(key + ":" + endpoint);
    }
}