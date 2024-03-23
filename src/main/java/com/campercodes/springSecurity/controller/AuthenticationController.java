package com.campercodes.springSecurity.controller;

import com.campercodes.springSecurity.model.AuthenticationResponse;
import com.campercodes.springSecurity.model.UserDto;
import com.campercodes.springSecurity.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

    @Autowired
    private UserService userService;

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationController.class);

    /**
     * This method is just present to register the user to DB.
     * @param user
     * @return
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody UserDto user) {
        AuthenticationResponse response;
        try {
            response = userService.registerUser(user);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        LOGGER.info("User registered: " + user.getUsername());
        return ResponseEntity.ok(response);
    }

    /**
     * This method is just present to enable other types of authentication.
     * @param request
     * @return
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody UserDto request) {
        LOGGER.info("Authenticate request with details" + request.getUsername());
        AuthenticationResponse response = userService.authenticateUser(request);
        return ResponseEntity.ok(response);
    }
}
