package com.campercodes.springSecurity.exception;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.rmi.ServerException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ServerException.class)
    public ResponseEntity<String> handleServletException(ServerException e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    }
}
