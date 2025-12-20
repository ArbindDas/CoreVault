package com.JSR.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponse {
    private String userId;
    private String email;
    private String username;
    private String fullName;
    private String firstName;
    private String lastName;
    private boolean emailVerified;
    private List<String> roles;
    private Map<String, Object> attributes;
}