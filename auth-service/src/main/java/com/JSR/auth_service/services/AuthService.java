package com.JSR.auth_service.services;

import com.JSR.auth_service.dto.LoginRequest;
import com.JSR.auth_service.dto.LoginResponse;
import com.JSR.auth_service.dto.SignupRequest;
import com.JSR.auth_service.dto.SignupResponse;


public interface AuthService {


    SignupResponse signup(SignupRequest request);
    LoginResponse login(LoginRequest request);


}
