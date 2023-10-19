package gwkim.security.checker;

import gwkim.security.domain.*;
import gwkim.security.repository.MemberRepository;
import gwkim.security.repository.MenuRepository;
import gwkim.security.service.MemberService;
import gwkim.security.service.MenuService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Transactional
public class AuthorizationChecker {
    private final MemberRepository memberRepository;
    private final MenuRepository menuRepository;
    private final MenuService menuService;
    private final MemberService memberService;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public boolean check(HttpServletRequest request, Authentication authentication) {
        String url = request.getRequestURI();
//        String method = request.getMethod().toUpperCase();

        Object principalObj = authentication.getPrincipal();

        // 로그인 여부 확인
        if(!(principalObj instanceof User)) {
            return false;
        }

        // 인증 여부 확인
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        if(ObjectUtils.isEmpty(userDetails.getMember())) {
            return false;
        }

        // url 권한 체크
        List<Long> authorGroupIdList = new ArrayList<>(); // 보유 권한 그룹
        List<String> allRole = new ArrayList<>(); // 보유한 모든 role
        Collection<GrantedAuthority> authorities = userDetails.getAuthorities();

        // 메뉴 권한 가져오기
        List<Long> menuAuthorList = menuService.getMenuAuthority(request.getRequestURI());

        if(menuAuthorList == null || menuAuthorList.isEmpty()) {
            return true;
        }

        // 회원 권한 가져오기
        String memberId = ((User) authentication.getPrincipal()).getUsername();
        List<Long> memberAuthorList = memberService.getMemberAuthority(memberId);

        // 메뉴 권한 체크
        if(!memberAuthorList.isEmpty()) {
            for (Long menuAuthor : memberAuthorList) {

                if(memberAuthorList.contains(menuAuthor)) {
                    return true;
                }
            }
        }
        return false;
    }
    
}
