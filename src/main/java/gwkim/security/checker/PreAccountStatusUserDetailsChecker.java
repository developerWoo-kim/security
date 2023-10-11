package gwkim.security.checker;

import gwkim.security.domain.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

@Slf4j
public class PreAccountStatusUserDetailsChecker implements UserDetailsChecker {
    @Override
    public void check(UserDetails toCheck) {
        CustomUserDetails user = (CustomUserDetails) toCheck;
        user.getMember().getMemberId();
    }
}
