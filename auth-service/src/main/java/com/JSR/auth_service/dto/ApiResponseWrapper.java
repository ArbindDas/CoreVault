package com.JSR.auth_service.dto;


import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Standard API response wrapper")
public class ApiResponseWrapper<T> {

    @Schema(description = "Response data")
    private T data;


//    📦 Shipping Box (ApiResponseWrapper<T>)
//├── 📋 Label (metadata: message, status, timestamp)
//└── 🎁 Contents (T data)
//    ├── If T=LoginResponse → Contains JWT token
//    ├── If T=SignupResponse → Contains user ID
//    ├── If T=UserDto → Contains user profile
//    └── If T=List<Product> → Contains products

    @Schema(description = "Response message", example = "Operation successful")
    private String message;

    @Schema(description = "HTTP status code ", example =  "200")
    private int status;

    @Schema(description = "Timestamp of the Response")
    private LocalDateTime timestamp;


    @Schema(description = "API version", example = "v1")
    private String version;

    @Schema(description = "Request ID for tracing")
    private String requestId;


    public static <T> ApiResponseWrapper<T>success(T data  , String message , int status){
        return ApiResponseWrapper.<T>builder()
                .data(data) // ← Your LoginResponse object goes here!
                .message(message)
                .status(status)
                .timestamp(LocalDateTime.now())
                .version("v1")
                .build();
    }


    public static <T> ApiResponseWrapper<T>error(String message, int status ,String errorCode){

        return ApiResponseWrapper.<T>builder()
                .data(null)
                .message(message)
                .status(status)
                .timestamp(LocalDateTime.now())
                .version("v1")
                .build();
    }

    // Add this overloaded version without errorCode if needed
    public static <T> ApiResponseWrapper<T> error(String message, int status) {
        return error(message, status, null);
    }
}
