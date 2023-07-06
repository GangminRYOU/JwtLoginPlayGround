package com.playground.jwt.api.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.playground.jwt.api.auth.domain.RefreshToken;
import com.playground.jwt.web.member.domain.Member;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
	Optional<RefreshToken> findByMemberAndToken(Member member, String token);
	Long deleteByMember(Member member);
}
