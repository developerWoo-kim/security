package gwkim.security.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter @Setter
@NoArgsConstructor
@Entity(name = "tb_au_author_group_role")
public class AuthorGroupRole {

    @Id
    @Column(name = "author_group_role_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long authorGroupRoleId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_group_id")
    private AuthorGroup authorGroup;
    private String authorGroupRoleName;

}
