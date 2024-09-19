package com.gwkim.security.basic.core.userdetails;

import com.gwkim.security.basic.port.in.SecurityMemberDto;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter @Setter
public class CustomUserDetails extends User {
    private static final long serialVersionUID = 23778217617823123L;
    private SecurityMemberDto member;


    public static CustomUserDetails of(String memberId, Collection<? extends GrantedAuthority> authorities) {
        return new CustomUserDetails(memberId, "", authorities);
    }

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public CustomUserDetails(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public boolean hasRole(String role) {
        Collection<GrantedAuthority> authorities = this.getAuthorities();

        for (GrantedAuthority authority : authorities) {
            String auth = authority.getAuthority();

            if(role.equals(auth)) {
                return true;
            }
        }

        return false;
    }
}
