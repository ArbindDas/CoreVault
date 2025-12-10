package com.JSR.auth_service.services.Impl;

import com.JSR.auth_service.Exception.UserNotFoundException;
import com.JSR.auth_service.dto.LoginRequest;
import com.JSR.auth_service.dto.SignupRequest;
import com.JSR.auth_service.dto.UserResponse;
import com.JSR.auth_service.entities.Users;
import com.JSR.auth_service.repository.UsersRepository;
import com.JSR.auth_service.services.AuthService;
import com.JSR.auth_service.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class AuthServiceImpl implements AuthService{


    private final UsersRepository usersRepository;


    @Autowired
    public AuthServiceImpl(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    @Override
    public UserResponse signup(SignupRequest request) {
        Users users = usersRepository.findByEmail(request.email())
                .orElseThrow(() -> new UserNotFoundException("User not found with -> "+ request.email()));



        return null;
    }

    @Override
    public String login(LoginRequest request) {
        return "";
    }
}
