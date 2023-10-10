package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 권한 관리 마스터 엔티티
 *
 * @author gwkim
 * @since 2023.08.23
 * @version 1.0
 */
@Entity(name = "tb_au_author")
@Getter @Setter
@NoArgsConstructor
public class Author {

    @Id
    @Column(name = "author_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long authorId;       // 권한 시퀀스

    private String authorCode;      // 권한 코드
    private String authorName;        // 권한 이름



}
