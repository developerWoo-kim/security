package gwkim.security.controller.error;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 로그인 실패 Error Controller
 *
 * @author kimgunwoo
 * @since 2023.10.13
 * @version 1.0
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthenticationErrorController {
    @Value("${security.login.fail.redirect-uri.default}")
    private String loginFailRedirect;

    @Value("${security.login.param.id}")
    private String loginParamId;

    private final AuthenticationErrorService authenticationErrorService;

    @PostMapping("/loginFailException")
    private String sendRedirectWithErrorMessage(HttpServletRequest request, HttpServletResponse response,
                                                RedirectAttributes redirectAttributes) {
        String redirectUri = loginFailRedirect;
        AuthenticationException exception = (AuthenticationException) request.getAttribute("exception");
        String memberId = (String) request.getParameter("username");
//                String exceptionMessage = AuthenticationMessageProvider.getExceptionMessage(exception);

        String exceptionMessage = authenticationErrorService.getErrorMessageByAuthenticationException(exception, memberId);
        redirectAttributes.addFlashAttribute("loginError", exceptionMessage);

        return "redirect:" + redirectUri;
    }
}
