package com.JSR.user_management_service.config;


import feign.Retryer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignRetryConfig {

    @Bean
    public Retryer feignRetryer(){
        return new Retryer.Default(
                1000,
                5000,
                3
        );
    }
}
