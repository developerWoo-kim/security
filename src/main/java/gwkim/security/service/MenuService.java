package gwkim.security.service;

import gwkim.security.domain.Menu;
import gwkim.security.repository.MenuRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MenuService {
    private final MenuRepository menuRepository;


    /**
     * 메뉴 권한 가져오기
     *
     * @param uri String : request Uri
     * @return List<Long>
     */
    public List<Long> getMenuAuthority(String uri) {
        List<Long> menuAuthor = null;           // 메뉴 권한
        for(Menu menu : menuRepository.findAll()) {
            if(new AntPathMatcher().match(menu.getMenuUrl(), uri)) {
                menuAuthor = menu.getAuthorGroupMenuList().stream()
                        .map(s -> s.getAuthorGroup().getAuthorGroupId())
                        .collect(Collectors.toList());
                break;
            }
        };
        return menuAuthor;
    }
}
