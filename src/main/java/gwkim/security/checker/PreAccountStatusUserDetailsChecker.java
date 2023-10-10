package gwkim.security.checker;

import gwkim.security.domain.SecurityUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

@Slf4j
public class PreAccountStatusUserDetailsChecker implements UserDetailsChecker {
    @Override
    public void check(UserDetails toCheck) {
        SecurityUser user = (SecurityUser) toCheck;
        user.getMember().getMemberId();
    }
}
