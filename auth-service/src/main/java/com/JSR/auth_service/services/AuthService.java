package com.JSR.auth_service.services;

import com.JSR.auth_service.dto.LoginRequest;
import com.JSR.auth_service.dto.SignupRequest;
import com.JSR.auth_service.dto.UserResponse;

public interface AuthService {


    UserResponse signup(SignupRequest request);
    String login(LoginRequest request);


}
