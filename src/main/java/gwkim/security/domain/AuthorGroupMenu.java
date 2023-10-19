package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "tb_au_author_group_menu")
public class AuthorGroupMenu {
    @Id
    @Column(name = "author_group_menu_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long authorGroupMenuId;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "menu_id")
    private Menu menu;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_group_id")
    private AuthorGroup authorGroup;
}
