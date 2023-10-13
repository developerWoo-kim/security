package gwkim.security.controller.error;

import gwkim.security.exception.AuthenticationExceptionTypes;
import gwkim.security.exception.AuthenticationMessageProvider;
import gwkim.security.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationErrorService {
    private final MemberService memberService;
    public String getErrorMessageByAuthenticationException(AuthenticationException exception, String memberId) {
        AuthenticationExceptionTypes exceptionTypes = AuthenticationMessageProvider.getExceptionMessage(exception);

        switch (exceptionTypes){
            // 비밀번호 틀렸을 경우
            case BadCredentialsException:
                return badCredentialsProcess(exceptionTypes, memberId);
            // 존재하지 않는 계정일 경우
            case UsernameNotFoundException:
            case AccountExpiredException:
            case CredentialsExpiredException:
            case DisabledException:
            case LockedException:
            case NoneException:
                return exceptionTypes.getValue();
            default:
                return AuthenticationExceptionTypes.NoneException.getValue();

        }
    }

    /**
     * 비밀번호 연속 실패 프로세스
     * 로그인 시도 횟수 증가 -> maxFailCount 도래 시 계정 상태 LOCKED
     *
     * @return String : AuthenticationExceptionTypes
     */
    public String badCredentialsProcess(AuthenticationExceptionTypes exceptionTypes, String memberId) {
        // 로그인 시도 횟수 증가
        memberService.incrementLoginFailCount(memberId);
        return exceptionTypes.getValue();
    }
}
