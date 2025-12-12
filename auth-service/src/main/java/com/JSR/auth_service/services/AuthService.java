package com.JSR.auth_service.services;

import com.JSR.auth_service.dto.LoginRequest;
import com.JSR.auth_service.dto.LoginResponse;
import com.JSR.auth_service.dto.SignupRequest;
import com.JSR.auth_service.dto.SignupResponse;

import java.util.concurrent.CompletableFuture;


public interface AuthService {


    SignupResponse signup(SignupRequest request);
    CompletableFuture<LoginResponse> login(LoginRequest request);


    void logout(String token, boolean logoutAllDevices);
     LoginResponse protectedLogin(LoginRequest request);

}
