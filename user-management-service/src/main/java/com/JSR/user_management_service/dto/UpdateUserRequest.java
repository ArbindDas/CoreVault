package com.JSR.user_management_service.dto;

import lombok.Data;

@Data
public class UpdateUserRequest {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Boolean emailVerified;
    private Boolean enabled;
}