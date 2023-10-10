package gwkim.security.controller;

import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequiredArgsConstructor
public class LoginController {
    private final MemberRepository memberRepository;

    /**
     * 관리자 로그인
     *
     * @param request
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/login")
    public void adminLogin(HttpServletRequest request,
                                             @RequestParam("username") String username,
                                             @RequestParam("password") String password) {
        // 회원의 Salt 조회
        String memberId = memberRepository.findById(username)
                .orElseThrow(() -> new RuntimeException("test")).getMemberId();
    }
}
