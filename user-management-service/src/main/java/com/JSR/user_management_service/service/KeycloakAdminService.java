package com.JSR.user_management_service.service;


import com.JSR.user_management_service.dto.CreateUserRequest;
import com.JSR.user_management_service.dto.UpdateUserRequest;
import com.JSR.user_management_service.dto.UserResponse;

import java.util.List;

public interface KeycloakAdminService {
    List<UserResponse> getAllUsers();
    UserResponse getUserById(String userId);
    String createUser(CreateUserRequest request);
    void updateUser(String userId, UpdateUserRequest request);
    void deleteUser(String userId);
    void sendVerificationEmail(String userId);
    void resetPassword(String userId, String newPassword, boolean temporary);
}