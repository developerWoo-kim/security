package gwkim.security.domain.dto;

import gwkim.security.domain.AuthorGroupMember;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthorGroupMemberDto {
    private Long authorGroupMemberId;
    private AuthorGroupDto authorGroup;
    public AuthorGroupMemberDto(AuthorGroupMember authorGroupMember) {
        this.authorGroupMemberId = authorGroupMember.getAuthorGroupMemberId();
        this.authorGroup = new AuthorGroupDto(authorGroupMember.getAuthorGroup());
    }
}
