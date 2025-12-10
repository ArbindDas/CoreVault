package com.JSR.auth_service.dto;


import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record JwtResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("username") String username,
        @JsonProperty("roles") List<String> roles
) {
    public JwtResponse(String token) {
        this(token, "Bearer", null, null);
    }
}