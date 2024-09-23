package com.gwkim.security.oauth2.domain;

import com.gwkim.security.oauth2.core.authentication.userdetails.SecurityUser;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.SecurityUserUseCase;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.form.SecurityUserSaveForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class SecurityUserServiceImpl implements SecurityUserUseCase {
    private final MemberRepository memberRepository;

    @Override
    public SecurityUser findById(String username) {
        Member member = memberRepository.findBySocialId(username);
        return member != null ? new SecurityUser(member.getSocialId(), member.getOwnerNm()) : null;
    }

    @Override
    public SecurityUser save(SecurityUserSaveForm userSaveForm) {
        Member member = userSaveForm.createMember();
        memberRepository.save(member);
        return new SecurityUser(member.getSocialId(), member.getOwnerNm());
    }
}
