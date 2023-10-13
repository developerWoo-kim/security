package gwkim.security.service;

import gwkim.security.custom.CustomGrantedAuthority;
import gwkim.security.domain.*;
import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    @Value("${security.login.fail.imsi-lock.lock-minute}")
    private Integer imsiLockLockMinute;

    @Value("${security.credentials-expired.month}")
    private Integer credentialsExpiredMonth;

    @Value("${security.credentials-expired.use}")
    private boolean credentialsExpiredUse;

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        ArrayList<GrantedAuthority> authorList = new ArrayList<>();

        Member member = memberRepository.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException("아이디 또는 비밀번호를 잘못 입력하셨습니다.\n입력하신 내용을 다시 확인해주세요."));

        // 2023.10.11 : 현 개발 시점에서 엔티티를 직접 사용해도 되는지 의문이 듭니다.
        // < ================ 권한 세팅 ================
        List<AuthorGroupMember> authorGroupMemberList = member.getAuthorGroupMemberList();
        for (AuthorGroupMember authorGroupMember : authorGroupMemberList) {
            AuthorGroup authorGroup = authorGroupMember.getAuthorGroup();
            List<AuthorGroupRole> roleList = authorGroup.getRoleList();
            for (AuthorGroupRole authorGroupRole : roleList) {
                authorGroupRole.getAuthorGroupRoleId();
            }

            authorList.add(new CustomGrantedAuthority(authorGroup));

        }
        // ================ 권한 세팅 ================ > //

        // < ================ 계정 상태 ================
        boolean enabled = true;                     // 활성화
        boolean credentialsNonExpired = true;       // 비밀번호 만료
        boolean accountNonLocked = true;            // 계정 잠김

        MemberType memberType = member.getMemberType();
        MemberStatus memberStatus = memberType.getMemberStatus(); // 계정 상태
        LoginPreventStatus loginPreventStatus = member.getLoginPreventStatus(); // 로그인 방지 상태

        if(memberStatus == MemberStatus.ACTIVE) {
            switch (loginPreventStatus) {
                case LOCKED:
                    accountNonLocked = false;
                    break;
                default:
                    break;
            }
        }

        // 비밀번호 만료일 체크
        if(credentialsExpiredUse) {
            credentialsNonExpired = this.checkCredentialsNonExpired(member.getPasswordUpdateDate());
        }

        // ================ 계정 상태 ================ > //

        // < ================ UserDetails 세팅 ================

        CustomUserDetails userDetails = new CustomUserDetails(member.getMemberId(), member.getMemberPassword(), enabled, true,
                credentialsNonExpired, accountNonLocked, authorList);
        userDetails.setMember(member);
        return userDetails;
    }

    private boolean checkCredentialsNonExpired(LocalDate passwordUpdateDate) {
        LocalDate toDate = LocalDate.now();
        LocalDate expiredDate = passwordUpdateDate.plusMonths(credentialsExpiredMonth);
        return toDate.isBefore(expiredDate);
    }
}
