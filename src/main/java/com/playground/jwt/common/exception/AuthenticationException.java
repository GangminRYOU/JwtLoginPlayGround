package com.playground.jwt.common.exception;


public class AuthenticationException extends BusinessException{
	public AuthenticationException(ErrorCode errorCode, String message) {
		super(errorCode, message);
	}

	public AuthenticationException(ErrorCode errorCode) {
		super(errorCode);
	}
}
