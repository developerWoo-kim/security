package com.gwkim.security.oauth2.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {

    Member findBySocialId(String socialId);
}
