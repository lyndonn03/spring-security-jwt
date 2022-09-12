package io.lpamintuan.securityjwt.controllers;

import java.time.LocalDateTime;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.lpamintuan.securityjwt.controllers.errors.AuthError;

@RestControllerAdvice
public class AppControllerAdvice {

    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public AuthError usernameNotFoundExceptionHandler(UsernameNotFoundException ex,
        HttpServletRequest req, HttpServletResponse res) {

        LocalDateTime timestamp = LocalDateTime.now();
        int status = HttpStatus.BAD_REQUEST.value();
        String error = "Bad Request";
        String content = ex.getMessage();
        String path = req.getPathInfo();

        return new AuthError(timestamp, status, error, content, path);

    }

    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public AuthError badCredentialsExceptionHandler(BadCredentialsException ex,
        HttpServletRequest req, HttpServletResponse res) {

        LocalDateTime timestamp = LocalDateTime.now();
        int status = HttpStatus.BAD_REQUEST.value();
        String error = "Bad Request";
        String content = ex.getMessage();
        String path = req.getPathInfo();

        return new AuthError(timestamp, status, error, content, path);

    }

}
