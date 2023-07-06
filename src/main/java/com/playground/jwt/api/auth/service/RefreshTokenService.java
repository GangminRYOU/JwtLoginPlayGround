package com.playground.jwt.api.auth.service;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import com.playground.jwt.config.JwtTokenProvider;


import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class RefreshTokenService {
	/*RefreshToken은 Access토큰이 만료되면 저장해둔것을 가져와서 비교해 AccessToken을 재발급 해야하기 때문에
	* 서버에 저장되어야 한다.
	* */

	private final JwtTokenProvider tokenProvider;
	private final RedisTemplate<String, String> redisTemplate;

	//로그인이 발생할때 마다 새로운 토큰을 발급해야하기 때문에 삭제 service를 따로 만들어 줬다.
	public void deleteTokenByEmail(String email){
		redisTemplate.delete(email);
	}

	public void saveRefreshToken(String email, String token){
			redisTemplate.opsForValue().set(email, token, tokenProvider.REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.MILLISECONDS);
	}

	public boolean validateToken(String token){
		if(!tokenProvider.validateToken(token)){
			return false;
		}
		String refreshToken = redisTemplate.opsForValue().get(tokenProvider.getUsernameFromToken(token));
		return refreshToken != null && refreshToken.equals(token);
	}

}
