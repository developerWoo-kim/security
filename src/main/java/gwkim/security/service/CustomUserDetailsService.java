package gwkim.security.service;

import gwkim.security.domain.Member;
import gwkim.security.domain.MemberStatus;
import gwkim.security.domain.SecurityUser;
import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    @Value("${security.login.fail.imsi-lock.lock-minute}")
    private Integer imsiLockLockMinute;

    @Value("${security.credentials-expired.month}")
    private Integer credentialsExpiredMonth;

    @Value("${security.credentials-expired.month}")
    private Integer getCredentialsExpiredMonth;

    @Value("${security.credentials-expired.use}")
    private boolean credentialsExpiredUse;

    private final MemberRepository memberRepository;



    @Override
    public UserDetails loadUserByUsername(String usernamem) throws UsernameNotFoundException {
        Member member = memberRepository.findById(usernamem).orElseThrow();
        SecurityUser user = new SecurityUser(member.getMemberId(), member.getMemberPassword(), new ArrayList<GrantedAuthority>());
        user.setMember(member);
        return user;
    }
}
