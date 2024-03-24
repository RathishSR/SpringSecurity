package com.campercodes.springSecurity.service;

import com.campercodes.springSecurity.entity.User;
import com.campercodes.springSecurity.model.AuthenticationResponse;
import com.campercodes.springSecurity.model.Role;
import com.campercodes.springSecurity.model.UserDto;
import com.campercodes.springSecurity.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthenticationResponse registerUser(UserDto userRequest) {
        User user = new User();
        user.setUsername(userRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        user.setRole(Role.valueOf(userRequest.getRole()));
        user.setEnabled(true);
        userRepository.save(user);
        log.info("User created: " + userRepository.findByUsername(userRequest.getUsername()));
        String jwt = jwtService.generateToken(user);
        return new AuthenticationResponse(jwt);
    }

    public AuthenticationResponse authenticateUser(UserDto request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()));

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username"));
        String jwt = jwtService.generateToken(user);
        return new AuthenticationResponse(jwt);
    }
}
