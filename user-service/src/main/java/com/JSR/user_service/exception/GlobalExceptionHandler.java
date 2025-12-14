package com.JSR.user_service.exception;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // todo -> When Triggerer when Endpoint/mapping not found
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorResponse>handleNoHandlerFoundException(Exception e , WebRequest request){
        ErrorResponse errorResponse = new ErrorResponse(
                e.getLocalizedMessage(),
                HttpStatus.NOT_FOUND.value(),
                request.getDescription(false).replace("uri=", ""),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(errorResponse , HttpStatus.NOT_FOUND);
    }


}
