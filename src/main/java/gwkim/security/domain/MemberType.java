package gwkim.security.domain;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity(name = "tb_mm_member_type")
@Getter
@Setter
@NoArgsConstructor
public class MemberType {
    @Id
    @Column(name = "member_type_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberTypeId;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;
    private String memberType;

    @Enumerated(EnumType.STRING)
    private MemberStatus memberStatus;
    private String confirmAt;
    private String confirmMemberId;
    private String confirmMemberName;
    private LocalDateTime confirmDateTime;

}
