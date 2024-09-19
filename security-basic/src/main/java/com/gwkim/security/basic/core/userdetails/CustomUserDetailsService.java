package com.gwkim.security.basic.core.userdetails;

import com.gwkim.security.basic.port.in.SecurityMemberDto;
import com.gwkim.security.basic.port.in.SecurityUserDetailsUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    private final SecurityUserDetailsUseCase securityUserDetailsUseCase;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SecurityMemberDto member = securityUserDetailsUseCase.findMember(username);
        if(member == null) {
            throw new UsernameNotFoundException(username);
        }

        // < ================ 권한 세팅 ================
        ArrayList<GrantedAuthority> authList = new ArrayList<>();

        for (String role : member.getRoleList()) {
            authList.add(new CustomGrantedAuthority(role));
        }

        // < ================ UserDetails 세팅 ================
        CustomUserDetails customUserDetails = new CustomUserDetails(member.getMemberId(), member.getPassword(), authList);

        // 회원 상태 체크 로직 있을 경우
//        CustomUserDetails userDetails = new CustomUserDetails(member.getMemberId(), member.getPassword(), enabled, true,
//                credentialsNonExpired, accountNonLocked, authorList);
        customUserDetails.setMember(member);
        return customUserDetails;
    }

}
