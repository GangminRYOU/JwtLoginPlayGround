package com.playground.jwt.web.member.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.playground.jwt.api.auth.dto.SignUpRequest;
import com.playground.jwt.common.exception.BusinessException;
import com.playground.jwt.common.exception.ErrorCode;
import com.playground.jwt.web.member.domain.Member;
import com.playground.jwt.web.member.domain.Role;
import com.playground.jwt.web.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;


	public Long save(SignUpRequest signUpRequest){
		validateDuplicateEmail(signUpRequest.getEmail());
		Member member = Member.builder()
			.email(signUpRequest.getEmail())
			.password(signUpRequest.getPassword())
			.role(Role.STUDENT)
			.build();
		member.encodePassword(passwordEncoder);
		Member savedMember = memberRepository.save(member);
		return savedMember.getId();
	}


	private void validateDuplicateEmail(String email){
		if(memberRepository.existsByEmail(email)){
			throw new BusinessException(ErrorCode.DUPLICATED_EMAIL);
		}
	}
}
