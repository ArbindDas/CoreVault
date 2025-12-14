package com.JSR.auth_service.controllers;

import com.JSR.auth_service.Exception.UserNotFoundException;
import com.JSR.auth_service.dto.*;
import com.JSR.auth_service.services.AuthService;
import com.JSR.auth_service.services.RateLimitService;
import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

@Slf4j
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
@CrossOrigin(
        origins = "http://localhost:5173",
        methods = { RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.OPTIONS },
        allowCredentials = "true",
        allowedHeaders = "*"
)
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    // Use THESE constants (correct format)
    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";


    private final RateLimitService rateLimitService;
    private final MeterRegistry meterRegistry;
    private final AuthService authService;

    @Autowired
    public AuthController(RateLimitService rateLimitService, MeterRegistry meterRegistry, AuthService authService) {
        this.rateLimitService = rateLimitService;
        this.meterRegistry = meterRegistry;
        this.authService = authService;
    }




    // Helper method to get client IP
    private String getClientIp(HttpServletRequest request) {
        // Check for X-Forwarded-For header (common when behind proxy/load balancer)
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, the first one is the original client
            return xfHeader.split(",")[0].trim();
        }

        // Fallback to remote address
        return request.getRemoteAddr();
    }


    @Operation(
            summary = "Register new user",
            description = "creates a new user account with provided details"
    )

    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "User Created Successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = SignupRequest.class)
                    )
            ),

            @ApiResponse(

                    responseCode = "400",
                    description = "Invalid input data",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = SignupRequest.class))
            ),

            @ApiResponse(
                    responseCode = "409",
                    description = "User Already exists",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = SignupRequest.class)
                    )
            ),

            @ApiResponse(
                    responseCode = "500",
                    description = "internal server error",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = SignupRequest.class)
                    )

            )
    })
    @PostMapping(
            value = "/signup",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )

    public ResponseEntity<ApiResponseWrapper<SignupResponse>> signup(
            @Parameter(description = "User registration details ", required = true)
            @Valid @RequestBody SignupRequest request,
            HttpServletRequest httpRequest) {

        log.info("Signup request received for email: {}", request.email());

        try {
            long startTime = System.currentTimeMillis();
            SignupResponse signupResponse = authService.signup(request);

            long processingTime = System.currentTimeMillis() - startTime;

            log.info("User registered successfully: {} (took {} ms)",
                    request.email(), processingTime);
            ApiResponseWrapper<SignupResponse> responseWrapper = ApiResponseWrapper.success(
                    signupResponse,  // Include the response data
                    "User Registered successfully",
                    HttpStatus.CREATED.value()
            );

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .header("X-Processing-Time", String.valueOf(processingTime))
                    .body(responseWrapper);

        } catch (Exception e) {
            log.error("Signup failed for email: {}, error: {}", request.email(), e.getMessage(), e);
            throw e;
        }
    }


    @Operation(
            summary = "User Login",
            description = "Authenticate user and returns JWT token"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class)
                    )
            ),


            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid credentials or input data",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class)
                    )
            ),

            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication Failed",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class)
                    )
            ),

            @ApiResponse(
                    responseCode = "423",
                    description = "Account locked",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))
            )
    })

    @PostMapping(value = "/signin",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<ApiResponseWrapper<LoginResponse>> signin(
            @Parameter(description = "User login credentials", required = true)
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Login attempt from ip {} for email: {}", clientIp, request.email());

        try {
            Long startTime = System.currentTimeMillis();

            // 1️⃣ RATE LIMITING (at controller level - PRODUCTION BEST PRACTICE)
            if (rateLimitService.isRateLimited("login:ip:" + clientIp, 100, Duration.ofMinutes(1))) {
                meterRegistry.counter("auth.rate_limit.ip").increment();
                log.warn("IP rate limit exceeded: {}", clientIp);
                return createRateLimitResponse("Too many requests from this IP");
            }

            if (rateLimitService.isRateLimited("login:user:" + request.email(), 100, Duration.ofMinutes(1))) {
                meterRegistry.counter("auth.rate_limit.user").increment();
                log.warn("User rate limit exceeded: {}", request.email());
                return createRateLimitResponse("Too many login attempts for this account");
            }

            // 2️⃣ CALL PROTECTED SERVICE (with circuit breaker & timeout)
            LoginResponse loginResponse = authService.protectedLogin(request);

            // 3️⃣ CHECK FOR SERVICE FAILURE (from fallback)
            if (loginResponse.token() == null) {
                // Service was unavailable (circuit breaker fallback triggered)
                meterRegistry.counter("auth.service_unavailable").increment();

                ApiResponseWrapper<LoginResponse> errorWrapper = ApiResponseWrapper.error(
                        "Authentication service is temporarily unavailable",
                        HttpStatus.SERVICE_UNAVAILABLE.value(),
                        "SERVICE_UNAVAILABLE"
                );
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .header("Retry-After", "30")
                        .body(errorWrapper);
            }

            Long processingTime = System.currentTimeMillis() - startTime;

            // 4️⃣ SUCCESS - Log metrics
            meterRegistry.counter("auth.login.success").increment();
            meterRegistry.timer("auth.login.duration").record(processingTime, TimeUnit.MILLISECONDS);

            log.info("Successfully login for user {} from ip {} (took {}ms)",
                    request.email(), clientIp, processingTime);

            ApiResponseWrapper<LoginResponse> responseWrapper = ApiResponseWrapper.success(
                    loginResponse,
                    "Login successful",
                    HttpStatus.OK.value()
            );

            return ResponseEntity.ok()
                    .header("X-Processing-Time", String.valueOf(processingTime))
                    .header("Authorization", "Bearer " + loginResponse.token())
                    .header("Access-Control-Expose-Headers", "Authorization, X-Processing-Time")
                    .body(responseWrapper);

        } catch (UserNotFoundException | BadCredentialsException e) {
            // Authentication failures (NOT service failures)
            meterRegistry.counter("auth.login.failure.authentication").increment();

            log.warn("Authentication failed for {} from {}: {}",
                    request.email(), clientIp, e.getMessage());

            ApiResponseWrapper<LoginResponse> errorWrapper = ApiResponseWrapper.error(
                    "Invalid email or password",
                    HttpStatus.UNAUTHORIZED.value(),
                    "AUTHENTICATION_FAILED"
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorWrapper);

        } catch (DisabledException e) {
            // Disabled account
            meterRegistry.counter("auth.login.failure.disabled").increment();

            ApiResponseWrapper<LoginResponse> errorWrapper = ApiResponseWrapper.error(
                    "Account is disabled",
                    HttpStatus.FORBIDDEN.value(),
                    "ACCOUNT_DISABLED"
            );
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorWrapper);

        } catch (Exception e) {
            // Unexpected errors
            meterRegistry.counter("auth.login.failure.unexpected").increment();

            log.error("Unexpected login error for {} from {}: {}",
                    request.email(), clientIp, e.getMessage(), e);

            ApiResponseWrapper<LoginResponse> errorWrapper = ApiResponseWrapper.error(
                    "Internal server error",
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "INTERNAL_ERROR"
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorWrapper);
        }
    }

    private ResponseEntity<ApiResponseWrapper<LoginResponse>> createRateLimitResponse(String message) {
        ApiResponseWrapper<LoginResponse> wrapper = ApiResponseWrapper.error(
                message,
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "RATE_LIMIT_EXCEEDED"
        );
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .header("X-RateLimit-Limit", "10")
                .header("X-RateLimit-Remaining", "0")
                .body(wrapper);
    }


    @Operation(
            summary = "User Logout",
            description = "Invalidates the current user's JWT token"
    )

    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Logout successful",
                    content = @Content(mediaType = "application/json")
            ),

            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid Token or missing Authorization header",
                    content = @Content(mediaType = "application/json")
            ),


            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - Invalid or Expired token",
                    content = @Content(mediaType = "application/json")
            ),

            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(mediaType = "application/json")
            )

    })

    @PostMapping(
            value = "/logout",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<ApiResponseWrapper<Void>> logout(
            HttpServletRequest httpRequest,
            @Parameter(description = "Logout from all devices ", required = false)
            @RequestParam(value = "allDevices", defaultValue = "false") boolean logoutAllDevices
    ) {
        String clientIp = getClientIp(httpRequest);

        // DON'T redefine these here - use the class-level constants
        String authorizeHeader = httpRequest.getHeader(AUTH_HEADER);

        log.info("Logout request from ip: {}, logoutAllDevices: {}", clientIp, logoutAllDevices);
        log.info("Authorization header value: {}", authorizeHeader);

        try {
            Long startTime = System.currentTimeMillis();

            // Check 1: Is header null?
            if (authorizeHeader == null) {
                log.error("Authorization header is NULL");
                throw new BadCredentialsException("Missing Authorization header");
            }

            // Check 2: Does it start with Bearer? (case-sensitive!)
            if (!authorizeHeader.startsWith(BEARER_PREFIX)) {
                log.error("Authorization header doesn't start with '{}'. Header: '{}'", BEARER_PREFIX, authorizeHeader);
                throw new BadCredentialsException("Invalid Authorization header format. Must start with 'Bearer '");
            }

            // Extract token
            String token = authorizeHeader.substring(BEARER_PREFIX.length()).trim();

            // Check 3: Is token empty?
            if (token.isEmpty()) {
                log.error("Token is empty after Bearer prefix");
                throw new BadCredentialsException("Token cannot be empty");
            }

            log.info("Extracted token length: {}", token.length());
            log.info("First 20 chars of token: {}", token.substring(0, Math.min(20, token.length())));

            // Call service to handle logout
            authService.logout(token, logoutAllDevices);

            Long processingTime = System.currentTimeMillis() - startTime;
            log.info("User logged out successfully from ip: {} (took {}ms)", clientIp, processingTime);

            ApiResponseWrapper<Void> responseWrapper = ApiResponseWrapper.success(
                    null,
                    logoutAllDevices ? "Logged out from all devices successfully" : "Logged out successfully",
                    HttpStatus.OK.value()
            );

            return ResponseEntity.ok()
                    .header("X-Processing-Time", String.valueOf(processingTime))
                    .body(responseWrapper);

        } catch (BadCredentialsException e) {
            log.warn("Authentication failed during logout from IP: {}, error: {}", clientIp, e.getMessage());

            // Return proper error response
            ApiResponseWrapper<Void> errorResponse = ApiResponseWrapper.error(
                    e.getMessage(),
                    HttpStatus.UNAUTHORIZED.value(),
                    "AUTH_ERROR"
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);

        } catch (Exception e) {
            log.error("Logout failed from IP: {}, error: {}", clientIp, e.getMessage(), e);

            ApiResponseWrapper<Void> errorResponse = ApiResponseWrapper.error(
                    "Logout failed: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "LOGOUT_ERROR"
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }



}