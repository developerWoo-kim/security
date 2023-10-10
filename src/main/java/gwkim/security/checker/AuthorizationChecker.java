package gwkim.security.checker;

import gwkim.security.domain.AuthorMember;
import gwkim.security.domain.AuthorMenu;
import gwkim.security.domain.Member;
import gwkim.security.domain.Menu;
import gwkim.security.repository.MemberRepository;
import gwkim.security.repository.MenuRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Transactional
public class AuthorizationChecker {
    private final MemberRepository memberRepository;
    private final MenuRepository menuRepository;

    public boolean check(HttpServletRequest request, Authentication authentication) {
//        String url = request.getRequestURI();
//        String method = request.getMethod().toUpperCase();

        Object principalObj = authentication.getPrincipal();

        if(!(principalObj instanceof User)) {
            return false;
        }

        boolean result = false;

        List<Long> authority = null;
        for(Menu menu : menuRepository.findAll()) {
            if(new AntPathMatcher().match(menu.getMenuUrl(), request.getRequestURI())) {
                authority = menu.getAuthorMenuList().stream()
                        .map(s -> s.getAuthor().getAuthorId())
                        .collect(Collectors.toList());
                break;
            }
        };

        if(authority == null) {
            return true;
        }

        // URL 매칭 시작
        String userId = ((User) authentication.getPrincipal()).getUsername();
        Optional<Member> byId = memberRepository.findById(userId);
        Member member = memberRepository.findById(userId).orElseThrow();
        List<Long> memberAuthorList = member.getAuthorMemberList().stream()
                .map(s -> s.getAuthor().getAuthorId())
                .collect(Collectors.toList());

        for (Long author : memberAuthorList) {
            if(authority.contains(author)) {
                result = true;
            };
        }

        return result;
    }
}
