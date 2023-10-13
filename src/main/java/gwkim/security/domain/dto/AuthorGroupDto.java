package gwkim.security.domain.dto;

import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.AuthorGroupRole;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class AuthorGroupDto {
    private Long authorGroupId;
    private String authorGroupName;
    private List<AuthorGroupRoleDto> roleList = new ArrayList<>();

    public AuthorGroupDto(AuthorGroup authorGroup) {
        this.authorGroupId = authorGroup.getAuthorGroupId();
        this.authorGroupName = authorGroup.getAuthorGroupName();
        List<AuthorGroupRole> list = authorGroup.getRoleList();
        for (AuthorGroupRole authorGroupRole : list) {
            roleList.add(new AuthorGroupRoleDto(authorGroupRole));
        }
    }
}
