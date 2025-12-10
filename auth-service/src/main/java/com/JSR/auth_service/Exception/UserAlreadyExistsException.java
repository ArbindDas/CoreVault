package com.JSR.auth_service.Exception;

public class UserAlreadyExistsException extends  RuntimeException{

    public UserAlreadyExistsException() {
        super("user already exists ");
    }

    public UserAlreadyExistsException(String message){
        super(message);
    }

    public UserAlreadyExistsException(String message , Throwable cause){
        super(message , cause);
    }

    public UserAlreadyExistsException (String field, String value){
        super("user already exists with "+ field + " : "+ value);
    }

    public static UserAlreadyExistsException withEmail(String email){
        return new UserAlreadyExistsException("user already exists with email -> "+ email);
    }

    public static UserAlreadyExistsException byId(Long id){
        return  new UserAlreadyExistsException("user already exists by id -> "+ id);
    }

}
