package com.playground.jwt.api.auth.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.playground.jwt.api.auth.dto.RefreshTokenRequest;
import com.playground.jwt.api.auth.dto.TokenResponse;
import com.playground.jwt.common.exception.AuthenticationException;
import com.playground.jwt.common.exception.ErrorCode;
import com.playground.jwt.config.JwtTokenProvider;
import com.playground.jwt.web.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtTokenService {
	private final JwtTokenProvider tokenProvider;
	private final RefreshTokenService refreshTokenService;
	private final MemberRepository memberRepository;

	/**
	 *
	 * @param email : 사용자의 unique값
	 * @param authentication : 로그인 인증후에 JwtLoginService에서 넘어오는 Authentication
	 * @return refreshToken
	 */
	private String createAndSaveRefreshToken(String email, Authentication authentication){
		String refreshToken = tokenProvider.createRefreshToken(authentication);
		refreshTokenService.deleteTokenByEmail(email);
		refreshTokenService.saveRefreshToken(email, refreshToken);
		return refreshToken;
	}

	/**
	 *
	 * @param username : LoginService에서 받아오는 email
	 * @param authentication : LoginService에서 인증후 받아오는 authentcation
	 * @return : 토큰 생성후 헤더에 담을 access, refresh token쌍
	 */
	public TokenResponse generateJwtTokens(String username, Authentication authentication){
		String accessToken = tokenProvider.createAccessToken(authentication);
		String refreshToken = createAndSaveRefreshToken(username, authentication);
		return new TokenResponse(accessToken, refreshToken);
	}

	public TokenResponse refreshJwtTokens(RefreshTokenRequest request){
		String currentRefreshToken = request.getRefreshToken();
		//이부분은 고려해볼만한 문제가 있다. TokenService -> RefreshTokenService -> TokenProvider로
		//가는 로직 : 역할 분리는 되었지만 조금 복잡하다. -> 일단 그냥 tokenprovider를 바로 사용하자
		validateRefreshToken(currentRefreshToken);
		//인증에 성공하면, Authentication을 다시 가져와서 토큰을 발급해주자, 그 뒤의 로직은 사실상 filter에서 로직이랑 같다.
		var authentication = tokenProvider.getAuthentication(currentRefreshToken);
		return generateJwtTokens(authentication.getName(), authentication);
	}

	//request에서 받아온 token이 우리가 발급해준것이 맞는지 검증한다.
	private void validateRefreshToken(String token){
		//Member를 찾아오기 위한 험난한 과정..
		String username = tokenProvider.getUsernameFromToken(token);
		if(!refreshTokenService.validateToken(token)){
			throw new AuthenticationException(ErrorCode.AUTHENTICATION_FAILURE);
		}
	}
}
