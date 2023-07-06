package com.playground.jwt.api.auth.domain;

import java.time.Instant;

import com.playground.jwt.web.member.domain.Member;
import com.playground.jwt.web.member.repository.MemberRepository;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/*Refresh토큰 - 멤버와 1대1 매핑*/
@Entity(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@OneToOne
	@JoinColumn(name = "member_id")
	private Member member;

	private String token;

	private Instant expiryDate;

	@Builder
	public RefreshToken(Member member, String token, Instant expiryDate) {
		this.member = member;
		this.token = token;
		this.expiryDate = expiryDate;
	}
}
