package gwkim.security.checker;

import gwkim.security.checker.exception.MemberInactiveException;
import gwkim.security.checker.exception.MemberLockedException;
import gwkim.security.checker.exception.MemberLoginCountOverException;
import gwkim.security.checker.exception.MemberNotApproveException;
import gwkim.security.domain.CustomUserDetails;
import gwkim.security.domain.Member;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

/**
 * Spring Security - 비밀번호 체크전 계정 상태 체킹
 */
@Slf4j
public class PreAccountStatusUserDetailsChecker implements UserDetailsChecker {

    @Override
    public void check(UserDetails toCheck) {
        CustomUserDetails userDetails = (CustomUserDetails) toCheck;
        Member member = userDetails.getMember();

        switch (userDetails.getMemberStatus()) {
            case WAITING:
            case REJECTED:
                throw new MemberNotApproveException("승인 대기 or 거절");
            case INACTIVE:
                throw new MemberInactiveException("휴면 계정");
            case ACTIVE:
                // 비밀번호 락 체크
                if(!userDetails.isAccountNonLocked()) {
                    throw new LockedException("연속 실패로 인한 계정 잠김");
                }
        }
    }
}
