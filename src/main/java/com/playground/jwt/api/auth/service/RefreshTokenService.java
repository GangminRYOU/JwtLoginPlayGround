package com.playground.jwt.api.auth.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.playground.jwt.api.auth.domain.RefreshToken;
import com.playground.jwt.api.auth.repository.RefreshTokenRepository;
import com.playground.jwt.common.exception.AuthenticationException;
import com.playground.jwt.common.exception.ErrorCode;
import com.playground.jwt.config.JwtTokenProvider;
import com.playground.jwt.web.member.domain.Member;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class RefreshTokenService {
	/*RefreshToken은 Access토큰이 만료되면 저장해둔것을 가져와서 비교해 AccessToken을 재발급 해야하기 때문에
	* 서버에 저장되어야 한다.
	* */
	private final RefreshTokenRepository refreshTokenRepository;
	private final JwtTokenProvider tokenProvider;
	private final RedisTemplate<String, String> redisTemplate;

	//로그인이 발생할때 마다 새로운 토큰을 발급해야하기 때문에 삭제 service를 따로 만들어 줬다.
	public void deleteTokenByMember(Member member){
		refreshTokenRepository.deleteByMember(member);
	}

	public void saveRefreshToken(RefreshToken token){
		refreshTokenRepository.save(token);
	}

	public boolean validateToken(Member member, String token){
		if(!tokenProvider.validateToken(token)){
			return false;
		}
		RefreshToken refreshToken = refreshTokenRepository.findByMemberAndToken(member, token)
			.orElseThrow(() -> new AuthenticationException(ErrorCode.REFRESH_TOKEN_NOT_FOUND));
		return refreshToken.getToken().equals(token);
	}

}
