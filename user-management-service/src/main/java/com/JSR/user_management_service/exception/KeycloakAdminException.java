package com.JSR.user_management_service.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class KeycloakAdminException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    public KeycloakAdminException(String message, HttpStatus status) {
        super(message);
        this.status = status;
        this.errorCode = "KEYCLOAK_" + status.value();
    }

    public KeycloakAdminException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public KeycloakAdminException(String message, HttpStatus status, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.errorCode = "KEYCLOAK_" + status.value();
    }

    public KeycloakAdminException(String message, HttpStatus status, String errorCode, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.errorCode = errorCode;
    }
}