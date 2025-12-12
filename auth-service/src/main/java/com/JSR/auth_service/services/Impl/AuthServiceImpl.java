package com.JSR.auth_service.services.Impl;

import com.JSR.auth_service.Exception.UserAlreadyExistsException;
import com.JSR.auth_service.Exception.UserNotFoundException;
import com.JSR.auth_service.dto.LoginRequest;
import com.JSR.auth_service.dto.LoginResponse;
import com.JSR.auth_service.dto.SignupRequest;
import com.JSR.auth_service.dto.SignupResponse;
import com.JSR.auth_service.entities.Roles;
import com.JSR.auth_service.entities.Users;
import com.JSR.auth_service.repository.RolesRepository;
import com.JSR.auth_service.repository.UsersRepository;
import com.JSR.auth_service.services.AuthService;
import com.JSR.auth_service.services.TokenBlacklistService;
import com.JSR.auth_service.utils.JwtUtil;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.timelimiter.annotation.TimeLimiter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;


@Service
@Slf4j
public class AuthServiceImpl implements AuthService{



    private final PasswordEncoder passwordEncoder;


    private final RolesRepository rolesRepository;


    private  final JwtUtil jwtUtil;

    private final UsersRepository usersRepository;


    private final TokenBlacklistService tokenBlacklistService; // We'll create this

    @Autowired
    public AuthServiceImpl(PasswordEncoder passwordEncoder,
                           RolesRepository rolesRepository,
                           JwtUtil jwtUtil,
                           UsersRepository usersRepository,
                           TokenBlacklistService tokenBlacklistService) {
        this.passwordEncoder = passwordEncoder;
        this.rolesRepository = rolesRepository;
        this.jwtUtil = jwtUtil;
        this.usersRepository = usersRepository;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    public SignupResponse signup(SignupRequest request) {
        if (usersRepository.existsByEmail(request.email())){
            throw new UserAlreadyExistsException("user already exists with email : -> "+request.email());
        }
        Users newUser = new Users();

        newUser.setFullName(request.fullName());
        newUser.setEmail(request.email());
        newUser.setPassword(passwordEncoder.encode(request.password()));
        newUser.setEnabled(true);
        newUser.setCreatedAt(LocalDateTime.now());
        newUser.setUpdatedAt(LocalDateTime.now());

        // Assign default role

        Roles userRole = rolesRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new UserNotFoundException("ROLE_USER not found in database"));

        newUser.getRoles().add(userRole);
        Users savedUser = usersRepository.save(newUser);
        return mapToResponse(savedUser);
    }

    public SignupResponse mapToResponse(Users user ){
        return new SignupResponse(
               user.getId(),
                user.getFullName(),
                user.getEmail(),
                null,
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }






    @Override
    public void logout(String token, boolean logoutAllDevices) {

        try {

            if (!jwtUtil.isTokenValid(token)){
                throw new BadCredentialsException("Invalid token");
            }

            // Extract username from token
            String username = jwtUtil.extractEmail(token);


            if (logoutAllDevices){
                // logout from all devices
                tokenBlacklistService.blacklistAllUserTokens(username);
                log.info("User {} logged out from all devices ", username);
            }else {
                // Logout only this token

                tokenBlacklistService.blacklistToken(token);
                log.info("User{} logged out from current  devices ", username);
            }
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
        }

    @Override
    public LoginResponse protectedLogin(LoginRequest request) {
        try {
            CompletableFuture<LoginResponse> future = login(request);
            return future.get(10, TimeUnit.SECONDS); // Wait for async result
        } catch (TimeoutException e) {
            log.error("Login timeout in protectedLogin: {}", e.getMessage());
            return new LoginResponse(null, null, null, null, null, Set.of("TIMEOUT"));
        } catch (Exception e) {
            log.error("Login error in protectedLogin: {}", e.getMessage());
            return new LoginResponse(null, null, null, null, null, Set.of("ERROR"));
        }
    }


    // ✅ CORRECT: Returns CompletableFuture for @TimeLimiter
    @CircuitBreaker(name = "authService", fallbackMethod = "serviceUnavailableFallback")
    @TimeLimiter(name = "authTimeout", fallbackMethod = "timeoutFallback")
    @Override
    public CompletableFuture<LoginResponse> login(LoginRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            Users users = usersRepository.findByEmail(request.email())
                    .orElseThrow(() -> new UserNotFoundException("user not found"));

            if (!passwordEncoder.matches(request.password(), users.getPassword())) {
                throw new BadCredentialsException("Invalid email or password");
            }
            if (!users.isEnabled()) {
                throw new DisabledException("User account is disabled");
            }

            String token = jwtUtil.generateToken(users.getEmail(), users.getRoles());
            tokenBlacklistService.storeActiveToken(users.getEmail(), token);

            return new LoginResponse(
                    token, "Bearer", users.getId(),
                    users.getFullName(), users.getEmail(),
                    users.getRoles().stream()
                            .map(Roles::getName)
                            .collect(Collectors.toSet())
            );
        });
    }

    // ✅ CORRECT: Returns CompletableFuture
    private CompletableFuture<LoginResponse> timeoutFallback(LoginRequest request, Throwable e) {
        log.warn("Login timeout: {}", e.getMessage());
        return CompletableFuture.completedFuture(
                new LoginResponse(null, null, null, null, null, Set.of("TIMEOUT"))
        );
    }

    // ✅ CORRECT: Returns CompletableFuture
    private CompletableFuture<LoginResponse> serviceUnavailableFallback(LoginRequest request, Throwable e) {
        log.error("Auth service unavailable: {}", e.getMessage());
        return CompletableFuture.completedFuture(
                new LoginResponse(null, null, null, null, null, Set.of("SERVICE_UNAVAILABLE"))
        );
    }


//
//    @Override
//    public LoginResponse login(LoginRequest request) {
//        Users users = usersRepository.findByEmail(request.email())
//                .orElseThrow(() -> new UserNotFoundException("user not found with email -> "+request.email()));
//
//        if (!passwordEncoder.matches(request.password(), users.getPassword())){
//            throw new BadCredentialsException("Invalid email or password");
//        }
//        if (!users.isEnabled()){
//            throw new DisabledException("User account is disabled");
//        }
//
//        String token = jwtUtil.generateToken(users.getEmail(), users.getRoles());
//
//
//        // ✅ Store token AFTER generation
//        tokenBlacklistService.storeActiveToken(users.getEmail(), token);
//
//        log.info("the generated jwt token is {}" , token);
//        log.info("User {} logged in with roles {}. JWT: {}",
//                users.getEmail(),
//                users.getRoles().stream().map(Roles::getName).collect(Collectors.toList()),
//                token);
//
//        return new LoginResponse(
//
//                token,
//                "Bearer",
//                users.getId(),
//                users.getFullName(),
//                users.getEmail(),
//                users.getRoles().stream()
//                        .map(Roles::getName)
//                        .collect(Collectors.toSet())
//        );
//
//
//    }




}
