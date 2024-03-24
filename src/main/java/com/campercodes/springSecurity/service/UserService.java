package com.campercodes.springSecurity.service;

import com.campercodes.springSecurity.entity.User;
import com.campercodes.springSecurity.model.AuthenticationResponse;
import com.campercodes.springSecurity.model.Role;
import com.campercodes.springSecurity.model.UserDto;
import com.campercodes.springSecurity.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public User loadUserByUsername(String username) {
        return userRepository
                .findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username"));
    }
}
