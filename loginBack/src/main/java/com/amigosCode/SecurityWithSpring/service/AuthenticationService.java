package com.amigosCode.SecurityWithSpring.service;

import com.amigosCode.SecurityWithSpring.controller.AuthenticationRequest;
import com.amigosCode.SecurityWithSpring.controller.AuthenticationResponse;
import com.amigosCode.SecurityWithSpring.controller.RegisterRequest;
import com.amigosCode.SecurityWithSpring.repository.UserRepository;
import com.amigosCode.SecurityWithSpring.user.AppUserRoles;
import com.amigosCode.SecurityWithSpring.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public User register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(AppUserRoles.USER)
                .build();
        repository.save(user);
        return user;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
            )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user , user.getFirstname() , user.getLastname() , user.getEmail() , user.getRoles());
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
