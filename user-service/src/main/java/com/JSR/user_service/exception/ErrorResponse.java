package com.JSR.user_service.exception;

import java.time.LocalDateTime;
public record ErrorResponse (
        String message,
        int status,
        String path,
        LocalDateTime localDateTime
){

}
