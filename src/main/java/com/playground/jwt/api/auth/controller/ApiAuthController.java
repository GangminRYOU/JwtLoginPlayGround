package com.playground.jwt.api.auth.controller;

import java.net.URI;

import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.playground.jwt.api.auth.dto.RefreshTokenRequest;
import com.playground.jwt.api.auth.dto.SignInRequest;
import com.playground.jwt.api.auth.dto.SignUpRequest;

import com.playground.jwt.api.auth.dto.TokenResponse;
import com.playground.jwt.api.auth.service.JwtLoginService;
import com.playground.jwt.api.auth.service.JwtTokenService;
import com.playground.jwt.web.member.service.MemberService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class ApiAuthController {

	private final MemberService memberService;
	private final JwtLoginService loginService;
	private final JwtTokenService tokenService;

	@PostMapping("/signup")
	public ResponseEntity<Void> saveOne(@RequestBody SignUpRequest memberRequest){
		Long savedId = memberService.save(memberRequest);
		return ResponseEntity.created(URI.create("/api/members/" + savedId)).build();
	}

	@PostMapping("/refresh")
	public ResponseEntity<TokenResponse> reissue(@RequestBody RefreshTokenRequest request){
		return ResponseEntity.ok().body(tokenService.refreshJwtTokens(request));
	}

	@PostMapping("/signin")
	public ResponseEntity<TokenResponse> login(@RequestBody SignInRequest loginRequest){
		/*발급한 토큰 쌍을 바디에 넘겨준다.*/
		return ResponseEntity.ok().body(loginService.authenticateUser(loginRequest));
	}
}
