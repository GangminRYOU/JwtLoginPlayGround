package com.playground.jwt.config;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component // SecurityConfig에서 등록해주어야 한다.
@RequiredArgsConstructor
/*Spring에서 오류가 터지고 잡아주지 않으면 WAS로 가서 BasicError머시기 컨트롤러를 호출해 필터를 2번 타는 경우가 있다.
* OncePerRequestFilter를 구현하면, 인증요청당 한번만 filter를 탄다.*/
public class JwtAuthTokenFilter extends OncePerRequestFilter {
	private final JwtTokenProvider tokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		//토큰은 로직 수행 도중에 변경되면 안된다.
		final String resolvedToken = resolveToken(request);
		//토큰 인증 로직 수행 - 1. Bearer토큰, 2. 토큰이 key로 해싱한 값과 같은지 확인
		if(StringUtils.hasText(resolvedToken) && tokenProvider.validateToken(resolvedToken)){
			Authentication authentication = tokenProvider.getAuthentication(resolvedToken);
			//authentication을 security context에 set해준다.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			log.info("Authenticated user : {}, uri : {}", authentication.getName(), request.getRequestURI());
		}
		//다른 필터로 넘기기
		filterChain.doFilter(request, response);
	}

	/*Token을 헤더에서 꺼내는 로직*/
	private String resolveToken(HttpServletRequest request){
		/*Token기반 인증 시스템은 bearer를 토큰 앞쪽에 포함하고 있다. 그 부분에 대해 확인 해주어야 한다.*/
		String bearerToken = request.getHeader("Authorization");
		if(bearerToken != null && bearerToken.startsWith("Bearer ")){
			//Bearer타입이면 앞쪽 Bearer를 떼고 Token내용만 반환한다.
			return bearerToken.substring("Bearer ".length());
		}
		//아니면 null반환
		return null;
	}

}
