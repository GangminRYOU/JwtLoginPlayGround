package com.playground.jwt.api.auth.dto;

import org.hibernate.validator.constraints.Range;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SignUpRequest {
	@NotBlank
	@Email
	private String email;
	@Range(min = 8, max = 24)
	private String password;
	private String role;
}
