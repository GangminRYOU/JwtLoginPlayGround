package com.playground.jwt.web.member.domain;

public enum Role {
	STUDENT("학생"), MENTOR("선생님"), ADMIN("운영진");

	private String explanation;

	Role(String explanation) {
		this.explanation = explanation;
	}
}
