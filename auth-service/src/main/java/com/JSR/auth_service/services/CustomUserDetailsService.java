package com.JSR.auth_service.services;
import com.JSR.auth_service.Exception.UserNotFoundException;
import com.JSR.auth_service.entities.Users;
import com.JSR.auth_service.repository.UsersRepository;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
//
// todo ->  Your CustomUserDetailsService is the bridge between your database and Spring Security,
// todo ->  providing Spring Security everything it needs (username, password, roles) to authenticate the user.
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UsersRepository usersRepository;

    @Override
    @Nullable
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        if (username.trim().isEmpty()) {
            throw new UsernameNotFoundException("Username cannot be null or empty");
        }

        Optional<Users> users = usersRepository.findByEmail(username.trim());
        if (users.isPresent()) {
            List<GrantedAuthority> authorities = users.get().getRoles()
                    .stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                    .collect(Collectors.toList());

            return org.springframework.security.core.userdetails.User.builder()
                    .username(users.get().getEmail())
                    .password(users.get().getPassword() != null ? users.get().getPassword(): "")
                    .authorities(authorities)
                    .build();
        }
        throw new UserNotFoundException("User not found with username: " + username);
    }
}
