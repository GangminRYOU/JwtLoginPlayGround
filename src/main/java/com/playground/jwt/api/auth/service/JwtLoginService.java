package com.playground.jwt.api.auth.service;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.playground.jwt.api.auth.dto.SignInRequest;
import com.playground.jwt.api.auth.dto.TokenResponse;
import com.playground.jwt.config.JwtTokenProvider;
import com.playground.jwt.web.member.repository.MemberRepository;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtLoginService {

	/*로그인 인증을 위한 Filter내의 인증 수행 AuthenticationManager*/
	private final AuthenticationManagerBuilder authenticationManagerBuilder;

	private final JwtTokenService tokenService;

	public TokenResponse authenticateUser(SignInRequest loginRequest){
		/*UsernamePasswordAuthenticationProvider가 사용하는 토큰*/
		var authenticationToken = new UsernamePasswordAuthenticationToken(
			loginRequest.getEmail(), loginRequest.getPassword());
		/*AuthenticationManager를 가져와 UsernamePasswordAuthenticationToken을 인증
		* 내부적으로 Provider를 타서 인증하고 Authentication을 가져온다.
		*
		* 이때 Authentication은 Principal, Credentials, Authorities를 가지고 있는데, 이는 UserDetailsService가 가져온 결과이다.
		* 성공하면
		* */
		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
		/*인증이 완료되면 SecurityContext에 저장한다.*/
		SecurityContextHolder.getContext().setAuthentication(authentication);
		/*토큰을 생성하고 반환한다.*/

		TokenResponse tokenResponse = tokenService.generateJwtTokens(loginRequest.getEmail(), authentication);
		return tokenResponse;
	}
}
