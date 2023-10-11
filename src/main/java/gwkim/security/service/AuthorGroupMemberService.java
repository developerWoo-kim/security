package gwkim.security.service;

import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.AuthorGroupMember;
import gwkim.security.domain.AuthorGroupRole;
import gwkim.security.domain.Member;
import gwkim.security.repository.AuthorGroupMemberRepository;
import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthorGroupMemberService {
    private final AuthorGroupMemberRepository authorGroupMemberRepository;
    private final MemberRepository memberRepository;

    private Member findAuthorGroupMember(String memberId) {
        Member member = memberRepository.findById(memberId).orElseThrow();

        List<AuthorGroupMember> authorGroupMemberList = member.getAuthorGroupMemberList();
        for (AuthorGroupMember authorGroupMember : authorGroupMemberList) {
            AuthorGroup authorGroup = authorGroupMember.getAuthorGroup();
            List<AuthorGroupRole> roleList = authorGroup.getRoleList();
            for (AuthorGroupRole authorGroupRole : roleList) {
                authorGroupRole.getAuthorGroupRoleId();
            }
        }

        return member;
    }
}

