package gwkim.security.domain.dto;

import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.AuthorGroupRole;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Data
@NoArgsConstructor
public class AuthorGroupRoleDto {
    private Long authorGroupRoleId;
    private String authorGroupRoleName;

    public AuthorGroupRoleDto(AuthorGroupRole authorGroupRole) {
        this.authorGroupRoleId = authorGroupRole.getAuthorGroupRoleId();
        this.authorGroupRoleName = authorGroupRole.getAuthorGroupRoleName();
    }
}
