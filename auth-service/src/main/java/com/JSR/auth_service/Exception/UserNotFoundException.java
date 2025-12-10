package com.JSR.auth_service.Exception;

public class UserNotFoundException extends RuntimeException{

    public UserNotFoundException() {
        super("user not found exception");
    }


    public UserNotFoundException(String message){
        super(message);
    }

    public UserNotFoundException(String message , Throwable cause){
        super(message , cause);
    }


    public static UserNotFoundException byId(Long id){
        return new UserNotFoundException("User not found with id -> "+ id);
    }

    public static UserNotFoundException byEmail(String email){
        return new UserNotFoundException("User not found with email -> "+ email);
    }

    public static UserNotFoundException byField(String field, String value) {
        return new UserNotFoundException("User not found with " + field + ": " + value);
    }
}
