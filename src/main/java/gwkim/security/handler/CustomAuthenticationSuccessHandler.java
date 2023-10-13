package gwkim.security.handler;

import gwkim.security.domain.CustomUserDetails;
import gwkim.security.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.ObjectUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Spring Security - 로그인 성공 핸들러
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final MemberService memberService;

    @Value("${security.login.success.redirect-uri}")
    private String successRedirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // 에러 세션 제거
        HttpSession session = request.getSession(false);
        if(!ObjectUtils.isEmpty(session)) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }

        // 로그인 시도 횟수 초기화
        memberService.resetLoginFailCount(userDetails.getUsername());

        // 리다이렉트
        response.sendRedirect(successRedirectUri);
    }
}
