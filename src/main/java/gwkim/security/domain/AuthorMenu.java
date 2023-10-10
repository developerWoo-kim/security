package gwkim.security.domain;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity(name = "tb_au_author_menu")
@Getter @Setter
@NoArgsConstructor
public class AuthorMenu {
    @Id
    @Column(name = "menu_author_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long menuAuthorId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id")
    private Author author;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "menu_id")
    private Menu menuManage;

}
