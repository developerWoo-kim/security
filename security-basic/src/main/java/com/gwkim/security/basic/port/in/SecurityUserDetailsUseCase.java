package com.gwkim.security.basic.port.in;

public interface SecurityUserDetailsUseCase {
    SecurityMemberDto findMember(String id);
}
