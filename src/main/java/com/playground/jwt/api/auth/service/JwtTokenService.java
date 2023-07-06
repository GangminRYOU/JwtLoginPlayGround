package com.playground.jwt.api.auth.service;

import java.time.Instant;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.playground.jwt.api.auth.domain.RefreshToken;
import com.playground.jwt.api.auth.dto.RefreshTokenRequest;
import com.playground.jwt.api.auth.dto.TokenResponse;
import com.playground.jwt.common.exception.AuthenticationException;
import com.playground.jwt.common.exception.BusinessException;
import com.playground.jwt.common.exception.ErrorCode;
import com.playground.jwt.config.JwtTokenProvider;
import com.playground.jwt.web.member.domain.Member;
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
		//JwtLoginService에서 들어오기 떄문에, email로 Member를 찾아서 RefreshTokenEntity생성
		Member member = memberRepository.findByEmail(email).orElseThrow(RuntimeException::new);
		RefreshToken tokenEntity = RefreshToken.builder()
			.member(member)
			.token(refreshToken)
			.expiryDate(Instant.now().plusMillis(tokenProvider.REFRESH_TOKEN_EXPIRE_TIME))
			.build();
		//새로 발급했으니 기존의 토큰은 삭제해준다.
		refreshTokenService.deleteTokenByMember(member);
		// -> 이 부분은 약간 계층을 너무 많이 나눈게 아닌가 생각
		refreshTokenService.saveRefreshToken(tokenEntity);
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
		Member member = memberRepository.findByEmail(username)
			.orElseThrow(() -> new BusinessException(ErrorCode.MEMBER_NOT_FOUND_ERROR));
		if(!refreshTokenService.validateToken(member, token)){
			throw new AuthenticationException(ErrorCode.AUTHENTICATION_FAILURE);
		}
	}


}
