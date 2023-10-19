package gwkim.security.service;

import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.AuthorGroupMember;
import gwkim.security.domain.AuthorGroupRole;
import gwkim.security.domain.Member;
import gwkim.security.domain.dto.AuthorGroupMemberDto;
import gwkim.security.repository.AuthorGroupMemberRepository;
import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthorGroupMemberService {
    private final MemberRepository memberRepository;

    public List<AuthorGroupMemberDto> findAuthorGroupMember(String memberId) {
        Member member = memberRepository.findById(memberId).orElseThrow();

        List<AuthorGroupMember> authorGroupMemberList = member.getAuthorGroupMemberList();
        List<AuthorGroupMemberDto> authorGroupMemberDtoList = new ArrayList<>();
        if(!authorGroupMemberList.isEmpty()) {
            for (AuthorGroupMember authorGroupMember : authorGroupMemberList) {
                authorGroupMemberDtoList.add(new AuthorGroupMemberDto(authorGroupMember));
            }
        }
        return authorGroupMemberDtoList;
    }
}

