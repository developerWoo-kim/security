package gwkim.security.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Getter @Setter
@NoArgsConstructor
@Entity(name = "tb_mm_member")
public class Member {
    @Id
    @Column(name = "member_id")
    private String memberId;            // 아이디
    private String memberName;          // 사용자명
    private String memberPassword;      // 사용자 비밀번호

    @OneToOne(mappedBy = "member", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private MemberType memberType;

    @JsonIgnore
    @OneToMany(mappedBy = "member")
    private List<AuthorMember> authorMemberList = new ArrayList<>();

    @JsonIgnore
    @OneToMany(mappedBy = "member")
    private List<AuthorGroupMember> authorGroupMemberList = new ArrayList<>();

    private LocalDate passwordUpdateDate;
}
