package gwkim.security.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


/**
 * Spring Security - UserDetails 커스텀
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@Getter @Setter
public class CustomUserDetails extends User {
    private static final long serialVersionUID = 23778217617823123L;

    private Member member;
    private MemberStatus memberStatus;

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.initStatus();
    }

    public CustomUserDetails(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired,
                             boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.initStatus();
    }

    private void initStatus() {
        this.memberStatus = MemberStatus.ACTIVE;
    }

}
