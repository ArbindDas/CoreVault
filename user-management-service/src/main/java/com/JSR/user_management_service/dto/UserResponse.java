package com.JSR.user_management_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Boolean emailVerified;
    private Boolean enabled;
    private Long createdTimestamp;
    private List<String> requiredActions;
    private Map<String, List<String>> attributes;
}