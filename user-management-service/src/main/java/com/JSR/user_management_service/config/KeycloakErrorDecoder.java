package com.JSR.user_management_service.config;

import com.JSR.user_management_service.exception.KeycloakAdminException;
import feign.Response;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Slf4j
@Component
public class KeycloakErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String methodKey, Response response) {
        String errorMessage = extractErrorMessage(response);
        HttpStatus status = HttpStatus.valueOf(response.status());

        // Map specific Keycloak error codes
        String errorCode = mapKeycloakErrorCode(response.status(), errorMessage);

        log.error("Keycloak API Error - Status: {}, Method: {}, Code: {}, Message: {}",
                status, methodKey, errorCode, errorMessage);

        return new KeycloakAdminException(
                "Keycloak API Error: " + errorMessage,
                status,
                errorCode
        );
    }

    private String extractErrorMessage(Response response) {
        try {
            if (response.body() != null) {
                return new BufferedReader(new InputStreamReader(response.body().asInputStream()))
                        .lines()
                        .collect(Collectors.joining("\n"));
            }
        } catch (IOException e) {
            log.warn("Failed to read error response body", e);
        }
        return "Unknown error occurred";
    }

    private String mapKeycloakErrorCode(int status, String errorMessage) {
        // Map common Keycloak errors to specific codes
        switch (status) {
            case 400:
                if (errorMessage.contains("User exists")) {
                    return "USER_ALREADY_EXISTS";
                } else if (errorMessage.contains("Invalid password")) {
                    return "INVALID_PASSWORD_FORMAT";
                }
                return "BAD_REQUEST";

            case 401:
                return "INVALID_ADMIN_CREDENTIALS";

            case 403:
                return "INSUFFICIENT_PRIVILEGES";

            case 404:
                return "USER_NOT_FOUND";

            case 409:
                return "RESOURCE_CONFLICT";

            default:
                return "KEYCLOAK_" + status;
        }
    }
}