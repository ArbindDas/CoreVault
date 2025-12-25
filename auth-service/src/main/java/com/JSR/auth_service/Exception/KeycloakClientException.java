package com.JSR.auth_service.Exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class KeycloakClientException extends RuntimeException {
    private final HttpStatus status;

    public KeycloakClientException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
}