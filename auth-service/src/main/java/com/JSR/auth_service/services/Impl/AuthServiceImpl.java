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
import com.JSR.auth_service.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.stream.Collectors;


@Service
@Slf4j
public class AuthServiceImpl implements AuthService{


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RolesRepository rolesRepository;


    @Autowired
    private JwtUtil jwtUtil;

    private final UsersRepository usersRepository;


    @Autowired
    public AuthServiceImpl(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
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
    public LoginResponse login(LoginRequest request) {
        Users users = usersRepository.findByEmail(request.email())
                .orElseThrow(() -> new UserNotFoundException("user not found with email -> "+request.email()));

        if (!passwordEncoder.matches(request.password(), users.getPassword())){
            throw new BadCredentialsException("Invalid email or password");
        }
        if (!users.isEnabled()){
            throw new DisabledException("User account is disabled");
        }

        String token = jwtUtil.generateToken(users.getEmail(), users.getRoles());

        log.info("the generated jwt token is {}" , token);
        log.info("User {} logged in with roles {}. JWT: {}",
                users.getEmail(),
                users.getRoles().stream().map(Roles::getName).collect(Collectors.toList()),
                token);

        return new LoginResponse(

                token,
                "Bearer",
                users.getId(),
                users.getFullName(),
                users.getEmail(),
                users.getRoles()
        );


    }

}
