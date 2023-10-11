package gwkim.security.domain;


import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "tb_au_author_group_member")
public class AuthorGroupMember {
    @Id
    @Column(name = "author_group_member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long authorGroupMemberId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_group_id")
    private AuthorGroup authorGroup;
}
