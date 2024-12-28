package com.lean.Security.auth;

import com.lean.Security.config.JwtServices;
import com.lean.Security.user.Role;
import com.lean.Security.user.User;
import com.lean.Security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtServices jwtServices;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        userRepository.save(user);
        var jwtToken = jwtServices.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken).build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(),authRequest.getPassword()
                )
        );
        var user = userRepository.findByEmail(authRequest.getEmail()).orElseThrow();
        var jwtToken = jwtServices.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken).build();
    }
}
