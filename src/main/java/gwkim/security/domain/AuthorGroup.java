package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Getter @Setter
@NoArgsConstructor
@Entity(name = "tb_au_author_group")
public class AuthorGroup {

    @Id
    @Column(name = "author_group_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long authorGroupId;
    private String authorGroupName;
    private String authorGroupDescription;

    @JsonIgnore
    @OneToMany(mappedBy = "authorGroup")
    private List<AuthorGroupRole> roleList = new ArrayList<>();

}
