package com.playground.jwt.common.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public enum ErrorCode {

	MEMBER_NOT_FOUND_ERROR(HttpStatus.NOT_FOUND, "E_001", "멤버를 찾을 수 없습니다."),
	DUPLICATED_EMAIL(HttpStatus.BAD_REQUEST, "E_002", "중복된 이메일"),
	AUTHENTICATION_FAILURE(HttpStatus.FORBIDDEN, "A_001", "인증 실패!"),
	REFRESH_TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "E_003", "리프레시 토큰을 찾을수 없습니다.");


	private HttpStatus httpStatus;
	private String errorCode;
	private String message;

	ErrorCode(HttpStatus httpStatus, String errorCode, String message) {
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
		this.message = message;

	}
}
