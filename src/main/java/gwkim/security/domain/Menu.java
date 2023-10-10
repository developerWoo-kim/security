package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity(name = "tb_mn_menu")
@Getter
@Setter
@NoArgsConstructor
public class Menu {
    @Id
    @Column(name = "menu_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long menuId;            // 메뉴 아이디
    private String menuName;          // 메뉴명
    private String menuType;          // 메뉴 타입
    private String menuUrl;         // 메뉴 url

    @JsonIgnore
    @OneToMany(mappedBy = "menuManage", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AuthorMenu> authorMenuList = new ArrayList<>();    // 메뉴 권한
}
