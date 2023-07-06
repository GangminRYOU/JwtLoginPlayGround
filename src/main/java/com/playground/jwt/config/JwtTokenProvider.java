package com.playground.jwt.config;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/*인증시 토큰을 발급해주는 클래스*/
@Component
@Slf4j
public class JwtTokenProvider {
	/* JWT토큰 발급을 위해 필요한 것
	* 1. SecretKey
	* 2. EXPIRE_TIME
	*
	* */

	//claim에 사용될 권한에 대한 키값
	private static final String AUTHORITIES_KEY = "auth";
	//진짜 서명에 사용될 키를 저장할 변수
	private Key key;

	//Base64 문자열로 인코딩된 값 byte로 변환 - key생성은 byte로 해야한다.
	@PostConstruct
	public void init(){
		byte[] secretKeyBytes = Decoders.BASE64.decode(base64Secret);
		this.key = Keys.hmacShaKeyFor(secretKeyBytes);
	}

	//application.yml에서 받아올 값을 저장할 변수
	private final String base64Secret;
	public final long REFRESH_TOKEN_EXPIRE_TIME;
	public final long ACCESS_TOKEN_EXPIRE_TIME;



	//보안을 위해 application.yml에 키를 저장한다.
	//생성자로 비밀키, 만료시간을 받는다.
	public JwtTokenProvider(
		@Value("${security.jwt.base64-secret}") String base64Secret,
		@Value("${security.jwt.refresh-expiration-time}") long refreshExpirationTime,
		@Value("${security.jwt.access-expiration-time}") long accessExpirationTime
	){
		this.base64Secret = base64Secret;
		this.REFRESH_TOKEN_EXPIRE_TIME = refreshExpirationTime;
		this.ACCESS_TOKEN_EXPIRE_TIME = accessExpirationTime;
	}

	/**
	 *
	 * @param authentication : JwtLoginService에서 id와 비밀번호로 인증하고 받은 인증정보
	 * @param expirationTime : application.yml에서 받아온값을 넣어줄건데, access와 refresh의 만료시간이 다르기 때문에, 파라미터로 넣어준다.
	 * @return : 토큰 발급
	 */
	public String createToken(Authentication authentication, long expirationTime){
		//UserDetails에서 Authentication에 부여된 권한들을 찾아본다.
		String authorities = authentication.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.joining(","));
		//JWT 토큰 생성 - 권한과 만료시간을 받아서 key를 생성한다.
		return Jwts.builder()
			.setSubject(authentication.getName())
			.claim(AUTHORITIES_KEY, authorities) // "auth" : "권한1, 권한2"
			.setIssuedAt(new Date(System.currentTimeMillis())) // 왜 Date?
			.setExpiration(new Date(System.currentTimeMillis() + expirationTime)) //발급시간 + 만료시간
			.signWith(key, SignatureAlgorithm.HS512)
			.compact();
	}

	//둘은 그냥 만료시간만 다르다.

	/*Access Token 생성*/
	public String createAccessToken(Authentication authentication){
		return createToken(authentication, ACCESS_TOKEN_EXPIRE_TIME);
	}

	/*Refresh Token 생성*/
	public String createRefreshToken(Authentication authentication){
		return createToken(authentication, REFRESH_TOKEN_EXPIRE_TIME);
	}

	/*필터 인증에서 토큰이 유혀한지 검증*/

	/**
	 *
	 * @param token : filter에서 header에 있던 token을 꺼내서 여기에 넣어준다.
	 * @return 가지고 있던 비밀키로 해싱한 뒤 서명을 비교하고 맞으면 claim들을 파싱한다.
	 */
	public boolean validateToken(String token){
		try{
			Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token);
			//여기서 인증에 문제가 생기면, JWTExceptoin이 터진다.
			return true;
		}catch (JwtException e){
			log.trace("Invalid JWT token trace{}", e.toString());
			return false;
		}

	}

	/**
	 *
	 * @param token : filter에서 resolve토큰한 값이 들어간다.
	 * @return
	 */

	public Authentication getAuthentication(String token){
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();
		Collection<? extends GrantedAuthority> authorities = Arrays
			//로그인 당시 "auth" : 권한1,권한2 이렇게 넣어준 권한들을 꺼내서 다시 해체한다.
			.stream(Optional.ofNullable(claims.get(AUTHORITIES_KEY))
				//문자열로 바꾼다.
				.map(Object::toString)
				//없으면 null문자열
				.orElse("")
				//있으면 ,로 split해서 권한1 권한2이렇게 배열로 만들어준다.
				.split(","))
			.map(String::trim)
			.filter(auth -> !auth.isEmpty())
			.map(SimpleGrantedAuthority::new)
			.toList();
		//원래 우리가 authorities를 넣어준 그때로 되돌리는 로직이다.

		//Principal생성
		User principal = new User(claims.getSubject(), "", authorities); // SimpleGrantedAuthroies의 리스트를 넣는다.
		// 우리가 사용하는 AuthenticationManager는 이메일, 비밀번호 기반의 인증이기 때문에, Username~~Provider? 를 사용하고
		//그 Provider는 UsernamePasswordAuthenticationToken만 받기 때문에 이 Token을 사욯해야한다.
		return new UsernamePasswordAuthenticationToken(principal, token, authorities);

	}

	//마찬가지로 해싱값을 비교후 맞으면 파싱해서 내부 정보를 가져옴
	//틀리면 예외
	public String getUsernameFromToken(String token){
		return Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
	}

}
