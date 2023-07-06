package com.playground.jwt.api.auth.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SignInRequest {
	private String email;
	private String password;

	@Builder
	public SignInRequest(String email, String password) {
		this.email = email;
		this.password = password;
	}
}
