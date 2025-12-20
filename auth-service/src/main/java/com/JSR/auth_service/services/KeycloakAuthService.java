package com.JSR.auth_service.services;

import com.JSR.auth_service.dto.*;

public interface KeycloakAuthService {
    SignupResponse createUser(SignupRequest request);
    LoginResponse login(LoginRequest request);
    TokenValidationResponse validateToken(String token);
    void logout(String token, boolean allDevices);
    void sendPasswordResetEmail(String email);
    void resendVerificationEmail(String email);
    UserInfoResponse getUserInfo(String token);
    TokenResponse refreshToken(String refreshToken);
    boolean checkEmailExists(String email);
    HealthCheckResponse healthCheck();
}