package com.JSR.auth_service.config;

//import com.JSR.auth_service.exception.KeycloakClientException;
import com.JSR.auth_service.Exception.KeycloakClientException;
import feign.Response;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@Slf4j
public class FeignErrorDecoder implements ErrorDecoder {

    private final ErrorDecoder defaultErrorDecoder = new Default();

    @Override
    public Exception decode(String methodKey, Response response) {
        if (response.status() >= 400) {
            String body = extractBody(response);
            log.error("Feign client error - Status: {}, Method: {}, Body: {}",
                    response.status(), methodKey, body);

            return switch (response.status()) {
                case 400 -> new KeycloakClientException("Bad request: " + body, HttpStatus.BAD_REQUEST);
                case 401 -> new KeycloakClientException("Unauthorized", HttpStatus.UNAUTHORIZED);
                case 403 -> new KeycloakClientException("Forbidden", HttpStatus.FORBIDDEN);
                case 404 -> new KeycloakClientException("Resource not found", HttpStatus.NOT_FOUND);
                default -> new KeycloakClientException(
                        "Keycloak API error: " + response.status() + " - " + body,
                        HttpStatus.valueOf(response.status())
                );
            };
        }
        return defaultErrorDecoder.decode(methodKey, response);
    }

    private String extractBody(Response response) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(response.body().asInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (IOException e) {
            return "Unable to read error response body";
        }
    }
}