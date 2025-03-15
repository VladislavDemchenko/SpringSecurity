package org.example.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalControllerHandler {

    @ExceptionHandler
    public ResponseEntity<String> handleNotFoundEmailException(NotFoundEmailException exception){
        return new ResponseEntity<>(exception.getMessage(), HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(BadCredentialsException.class) // incorrect email is handled before password
    public ResponseEntity<String> handleBadCredentialsException() {
        return new ResponseEntity<>("Incorrect password. Please try again.", HttpStatus.UNAUTHORIZED);
    }
}
