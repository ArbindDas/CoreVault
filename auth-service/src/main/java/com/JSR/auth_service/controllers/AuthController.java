    package com.JSR.auth_service.controllers;

    import com.JSR.auth_service.dto.*;
    import com.JSR.auth_service.dto.ApiResponseWrapper;
    import com.JSR.auth_service.services.KeycloakAuthService;
    import com.JSR.auth_service.services.RateLimitService;
    import io.github.bucket4j.Bucket;
    import io.micrometer.core.instrument.MeterRegistry;
    import io.swagger.v3.oas.annotations.Operation;
    import io.swagger.v3.oas.annotations.media.Content;
    import io.swagger.v3.oas.annotations.media.Schema;
    import io.swagger.v3.oas.annotations.responses.ApiResponse;
    import io.swagger.v3.oas.annotations.responses.ApiResponses;
    import io.swagger.v3.oas.annotations.tags.Tag;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.validation.Valid;
    import lombok.RequiredArgsConstructor;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.http.HttpStatus;
    import org.springframework.http.MediaType;
    import org.springframework.http.ResponseEntity;
    import org.springframework.web.bind.annotation.*;

    import java.time.Duration;
    import java.util.Collections;
    import java.util.Date;

    @Slf4j
    @Tag(name = "Authentication", description = "Authentication and authorization endpoints using Keycloak")
    @RestController
    @RequestMapping("/api/v1/auth")
    public class AuthController {

        private final KeycloakAuthService keycloakAuthService;
        private final RateLimitService rateLimitService;
        private final MeterRegistry meterRegistry;


        public AuthController(KeycloakAuthService keycloakAuthService, RateLimitService rateLimitService, MeterRegistry meterRegistry) {
            this.keycloakAuthService = keycloakAuthService;
            this.rateLimitService = rateLimitService;
            this.meterRegistry = meterRegistry;
        }


        @GetMapping("/test")
        public String test() {
            return "Auth Service is working! Time: " + new Date();
        }

        /**
         * Signup - Create new user in Keycloak
         */
        @Operation(summary = "Register a new user",
                description = "Creates a new user account in Keycloak and sends verification email")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "201", description = "User created successfully",
                        content = @Content(schema = @Schema(implementation = SignupResponse.class))),
                @ApiResponse(responseCode = "400", description = "Invalid input data"),
                @ApiResponse(responseCode = "409", description = "User already exists"),
                @ApiResponse(responseCode = "429", description = "Too many requests"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<SignupResponse>> signup(
                @Valid @RequestBody SignupRequest signupRequest,
                HttpServletRequest request) {

            log.info("Signup request for email: {}", signupRequest.getEmail());

            // Check rate limiting
            String clientIp = getClientIp(request);
            Bucket bucket = rateLimitService.resolveBucket(clientIp, "signup");

            if (!bucket.tryConsume(1)) {
                log.warn("Rate limit exceeded for signup from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(ApiResponseWrapper.error("Too many signup attempts. Please try again later."));
            }

            try {
                // Create user in Keycloak
                SignupResponse response = keycloakAuthService.createUser(signupRequest);

                // Track metrics
                meterRegistry.counter("auth.signup.success").increment();

                log.info("User created successfully: {}", signupRequest.getEmail());

                return ResponseEntity.status(HttpStatus.CREATED)
                        .body(ApiResponseWrapper.success(response,
                                "Registration successful! Please check your email to verify your account."));

            } catch (IllegalArgumentException e) {
                meterRegistry.counter("auth.signup.validation_error").increment();
                log.warn("Signup validation error: {}", e.getMessage());
                return ResponseEntity.badRequest()
                        .body(ApiResponseWrapper.error(e.getMessage()));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.signup.error").increment();
                log.error("Signup failed for {}: {}", signupRequest.getEmail(), e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponseWrapper.error(e.getMessage()));

            } catch (Exception e) {
                meterRegistry.counter("auth.signup.error").increment();
                log.error("Unexpected error during signup: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Registration failed. Please try again later."));
            }
        }

        /**
         * Login - Authenticate user with Keycloak
         * Note: This is optional since frontend can login directly to Keycloak
         */
        @Operation(summary = "Login user",
                description = "Authenticate user with Keycloak and get tokens")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Login successful",
                        content = @Content(schema = @Schema(implementation = LoginResponse.class))),
                @ApiResponse(responseCode = "400", description = "Invalid credentials"),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(responseCode = "429", description = "Too many requests"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<LoginResponse>> login(
                @Valid @RequestBody LoginRequest loginRequest,
                HttpServletRequest request) {

            log.info("Login request for username: {}", loginRequest.getEmail());

            // Check rate limiting
            String clientIp = getClientIp(request);
            Bucket bucket = rateLimitService.resolveBucket(clientIp, "login");

            if (!bucket.tryConsume(1)) {
                log.warn("Rate limit exceeded for login from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(ApiResponseWrapper.error("Too many login attempts. Please try again later."));
            }

            try {
                // Authenticate with Keycloak
                LoginResponse response = keycloakAuthService.login(loginRequest);

                // Track metrics
                meterRegistry.counter("auth.login.success").increment();

                log.info("Login successful for: {}", loginRequest.getEmail());

                return ResponseEntity.ok(ApiResponseWrapper.success(response, "Login successful"));

            } catch (IllegalArgumentException e) {
                meterRegistry.counter("auth.login.invalid_credentials").increment();
                log.warn("Login failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Invalid username or password"));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.login.error").increment();
                log.error("Login error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error(e.getMessage()));

            } catch (Exception e) {
                meterRegistry.counter("auth.login.error").increment();
                log.error("Unexpected login error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Login failed. Please try again later."));
            }
        }

        /**
         * Validate Token - Check if Keycloak token is valid
         */
        @Operation(summary = "Validate JWT token",
                description = "Validate Keycloak JWT token and get user info")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Token is valid",
                        content = @Content(schema = @Schema(implementation = TokenValidationResponse.class))),
                @ApiResponse(responseCode = "401", description = "Token is invalid or expired"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/validate-token", produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<TokenValidationResponse>> validateToken(
                @RequestHeader(value = "Authorization", required = false) String authHeader) {

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Missing or invalid Authorization header"));
            }

            String token = authHeader.substring(7);

            try {
                TokenValidationResponse response = keycloakAuthService.validateToken(token);

                meterRegistry.counter("auth.token.validation.success").increment();

                return ResponseEntity.ok(ApiResponseWrapper.success(response, "Token is valid"));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.token.validation.failed").increment();
                log.warn("Token validation failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Invalid or expired token"));

            } catch (Exception e) {
                meterRegistry.counter("auth.token.validation.error").increment();
                log.error("Token validation error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Token validation failed"));
            }
        }

        /**
         * Logout - Invalidate Keycloak token
         */
        @Operation(summary = "Logout user",
                description = "Invalidate Keycloak token (logout from all devices if specified)")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Logout successful"),
                @ApiResponse(responseCode = "401", description = "Invalid token"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<Void>> logout(
                @RequestHeader("Authorization") String authHeader,
                @RequestParam(value = "allDevices", defaultValue = "false") boolean allDevices) {

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Missing or invalid Authorization header"));
            }

            String token = authHeader.substring(7);

            try {
                keycloakAuthService.logout(token, allDevices);

                meterRegistry.counter("auth.logout.success").increment();

                return ResponseEntity.ok(ApiResponseWrapper.success(null,
                        allDevices ? "Logged out from all devices" : "Logged out successfully"));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.logout.error").increment();
                log.warn("Logout failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Logout failed: " + e.getMessage()));

            } catch (Exception e) {
                meterRegistry.counter("auth.logout.error").increment();
                log.error("Logout error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Logout failed"));
            }
        }

        /**
         * Forgot Password - Send password reset email
         */
        @Operation(summary = "Forgot password",
                description = "Send password reset email to user")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Password reset email sent"),
                @ApiResponse(responseCode = "404", description = "User not found"),
                @ApiResponse(responseCode = "429", description = "Too many requests"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/forgot-password", consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<Void>> forgotPassword(
                @Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest,
                HttpServletRequest request) {

            log.info("Forgot password request for email: {}", forgotPasswordRequest.getEmail());

            // Check rate limiting
            String clientIp = getClientIp(request);
            Bucket bucket = rateLimitService.resolveBucket(clientIp, "forgot-password");

            if (!bucket.tryConsume(1)) {
                log.warn("Rate limit exceeded for forgot-password from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(ApiResponseWrapper.error("Too many password reset attempts. Please try again later."));
            }

            try {
                keycloakAuthService.sendPasswordResetEmail(forgotPasswordRequest.getEmail());

                meterRegistry.counter("auth.forgot_password.success").increment();

                return ResponseEntity.ok(ApiResponseWrapper.success(null,
                        "Password reset email sent. Please check your inbox."));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.forgot_password.error").increment();
                log.warn("Forgot password failed: {}", e.getMessage());

                // Don't reveal if user exists or not (security)
                return ResponseEntity.ok(ApiResponseWrapper.success(null,
                        "If an account exists with this email, a password reset link has been sent."));

            } catch (Exception e) {
                meterRegistry.counter("auth.forgot_password.error").increment();
                log.error("Forgot password error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Failed to send password reset email"));
            }
        }

        /**
         * Resend Verification Email
         */
        @Operation(summary = "Resend verification email",
                description = "Resend email verification link to user")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Verification email sent"),
                @ApiResponse(responseCode = "404", description = "User not found"),
                @ApiResponse(responseCode = "429", description = "Too many requests"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/resend-verification", consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<Void>> resendVerification(
                @Valid @RequestBody ResendVerificationRequest resendRequest,
                HttpServletRequest request) {

            log.info("Resend verification request for email: {}", resendRequest.getEmail());

            // Check rate limiting
            String clientIp = getClientIp(request);
            Bucket bucket = rateLimitService.resolveBucket(clientIp, "resend-verification");

            if (!bucket.tryConsume(1)) {
                log.warn("Rate limit exceeded for resend-verification from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(ApiResponseWrapper.error("Too many verification email requests. Please try again later."));
            }

            try {
                keycloakAuthService.resendVerificationEmail(resendRequest.getEmail());

                meterRegistry.counter("auth.resend_verification.success").increment();

                return ResponseEntity.ok(ApiResponseWrapper.success(null,
                        "Verification email sent successfully."));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.resend_verification.error").increment();
                log.warn("Resend verification failed: {}", e.getMessage());

                // Don't reveal if user exists or not
                return ResponseEntity.ok(ApiResponseWrapper.success(null,
                        "If an account exists with this email, a verification email has been sent."));

            } catch (Exception e) {
                meterRegistry.counter("auth.resend_verification.error").increment();
                log.error("Resend verification error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Failed to send verification email"));
            }
        }

        /**
         * Health Check - Verify Keycloak connection
         */
        @Operation(summary = "Auth service health check",
                description = "Check if auth service and Keycloak are operational")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Service is healthy"),
                @ApiResponse(responseCode = "503", description = "Service unavailable")
        })
        @GetMapping("/health")
        public ResponseEntity<ApiResponseWrapper<HealthCheckResponse>> healthCheck() {
            try {
                HealthCheckResponse response = keycloakAuthService.healthCheck();

                if (response.isKeycloakHealthy()) {
                    return ResponseEntity.ok(ApiResponseWrapper.success(response, "Auth service is healthy"));
                } else {
                    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                            .body(ApiResponseWrapper.error(response, "Keycloak is unavailable"));
                }

            } catch (Exception e) {
                log.error("Health check failed: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(ApiResponseWrapper.error("Auth service is unavailable"));
            }
        }

        /**
         * Get User Info - Get user details from Keycloak
         */
        @Operation(summary = "Get user info",
                description = "Get user information from Keycloak using JWT token")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "User info retrieved",
                        content = @Content(schema = @Schema(implementation = UserInfoResponse.class))),
                @ApiResponse(responseCode = "401", description = "Invalid token"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @GetMapping(value = "/user-info", produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<UserInfoResponse>> getUserInfo(
                @RequestHeader("Authorization") String authHeader) {

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Missing or invalid Authorization header"));
            }

            String token = authHeader.substring(7);

            try {
                UserInfoResponse response = keycloakAuthService.getUserInfo(token);

                return ResponseEntity.ok(ApiResponseWrapper.success(response, "User info retrieved successfully"));

            } catch (RuntimeException e) {
                log.warn("Get user info failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseWrapper.error("Invalid or expired token"));

            } catch (Exception e) {
                log.error("Get user info error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Failed to get user info"));
            }
        }

        /**
         * Refresh Token - Get new access token using refresh token
         */
        @Operation(summary = "Refresh access token",
                description = "Get new access token using refresh token")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                        content = @Content(schema = @Schema(implementation = TokenResponse.class))),
                @ApiResponse(responseCode = "400", description = "Invalid refresh token"),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @PostMapping(value = "/refresh-token", consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseWrapper<TokenResponse>> refreshToken(
                @Valid @RequestBody RefreshTokenRequest refreshRequest) {

            try {
                TokenResponse response = keycloakAuthService.refreshToken(refreshRequest.getRefreshToken());

                meterRegistry.counter("auth.token.refresh.success").increment();

                return ResponseEntity.ok(ApiResponseWrapper.success(response, "Token refreshed successfully"));

            } catch (RuntimeException e) {
                meterRegistry.counter("auth.token.refresh.failed").increment();
                log.warn("Token refresh failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseWrapper.error("Invalid refresh token"));

            } catch (Exception e) {
                meterRegistry.counter("auth.token.refresh.error").increment();
                log.error("Token refresh error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Failed to refresh token"));
            }
        }

        /**
         * Check if email exists
         */
        @Operation(summary = "Check email availability",
                description = "Check if email is already registered in Keycloak")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "Email check completed",
                        content = @Content(schema = @Schema(implementation = EmailCheckResponse.class))),
                @ApiResponse(responseCode = "500", description = "Internal server error")
        })
        @GetMapping("/check-email/{email}")
        public ResponseEntity<ApiResponseWrapper<EmailCheckResponse>> checkEmail(
                @PathVariable String email) {

            try {
                boolean exists = keycloakAuthService.checkEmailExists(email);

                EmailCheckResponse response = EmailCheckResponse.builder()
                        .email(email)
                        .exists(exists)
                        .message(exists ? "Email already registered" : "Email available")
                        .build();

                return ResponseEntity.ok(ApiResponseWrapper.success(response,
                        exists ? "Email already exists" : "Email is available"));

            } catch (Exception e) {
                log.error("Email check error: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponseWrapper.error("Failed to check email availability"));
            }
        }

        /**
         * Get client IP address
         */
        private String getClientIp(HttpServletRequest request) {
            String xfHeader = request.getHeader("X-Forwarded-For");
            if (xfHeader != null) {
                return xfHeader.split(",")[0];
            }
            return request.getRemoteAddr();
        }
    }