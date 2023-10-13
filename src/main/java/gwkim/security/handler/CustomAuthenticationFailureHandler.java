package gwkim.security.handler;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Spring Security - 로그인 실패 핸들러
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@Slf4j
@NoArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Value("${security.login.fail.redirect-uri.default}")
    private String loginFailRedirectDefault;

    @Value("${security.login.fail.imsi-lock.max-count}")
    private Integer imsiLockMaxCount;

    @Value("${security.login.fail.imsi-lock.lock-minute}")
    private long imsiLockLockMinute;

    @Value("${security.login.fail.imsi-lock.use}")
    private boolean imsiLockUse;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String forwardPath = "/loginFailException";
        request.setAttribute("exception", exception);
        request.getRequestDispatcher(forwardPath).forward(request, response);
    }
}
