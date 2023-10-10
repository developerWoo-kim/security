package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

/**
 * 회원 권한 관리 엔티티
 *
 * @author gwkim
 * @since 2023.08.23
 * @version 1.0
 */
@Entity(name = "tb_au_author_member")
@Getter
@Setter
@NoArgsConstructor
public class AuthorMember {

    @Id
    @Column(name = "member_author_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberAuthorId;   // 사용자 권한 번호

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id")
    private Author author;

    /**
     * 회원의 권한 생성
     *
     * @param member
     * @param author
     * @return
     */
    public static AuthorMember createAuthorMember(Member member, Author author) {
        AuthorMember authorMember = new AuthorMember();
        authorMember.setMember(member);
        authorMember.setAuthor(author);
        return authorMember;
    }
}
