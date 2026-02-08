package com.example.jwt_authenticator.exception;

public class UserAlreadyExistsException extends AppException {
    public UserAlreadyExistsException(String message) {
        super(message, ErrorCode.USER_ALREADY_EXIST);
    }
}