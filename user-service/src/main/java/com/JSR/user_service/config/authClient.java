package com.JSR.user_service.config;


import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "auth-service")
public interface authClient {

}
