package com.JSR.user_management_service.exception;


import com.JSR.user_management_service.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(KeycloakAdminException.class)
    public ResponseEntity<ApiResponse<Void>> handleKeycloakAdminException(KeycloakAdminException ex) {
        log.error("Keycloak API Error: {}", ex.getMessage(), ex);

        return ResponseEntity.status(ex.getStatus())
                .body(ApiResponse.<Void>error(
                        ex.getMessage(),
                        null
                ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.<Void>error(
                        "Access denied. You don't have permission to perform this action.",
                        null
                ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.<Void>error(
                        "An unexpected error occurred. Please try again later.",
                        null
                ));
    }
}