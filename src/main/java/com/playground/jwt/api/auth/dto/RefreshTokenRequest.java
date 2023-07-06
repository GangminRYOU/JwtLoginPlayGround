package com.playground.jwt.api.auth.dto;

import org.springframework.web.bind.annotation.GetMapping;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RefreshTokenRequest {
	@JsonProperty("refresh_token")
	private String refreshToken;

	@Builder
	public RefreshTokenRequest(String refreshToken) {
		this.refreshToken = refreshToken;
	}
}
