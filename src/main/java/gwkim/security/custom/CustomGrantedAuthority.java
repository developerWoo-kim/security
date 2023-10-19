package gwkim.security.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.dto.AuthorGroupDto;
import gwkim.security.domain.dto.AuthorGroupMemberDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = -51255679987025341L;
    private final String groupName;

    @Getter
    private final AuthorGroupDto authorGroup;
    public CustomGrantedAuthority(AuthorGroupMemberDto authorGroupMemberDto) {
        this.groupName = authorGroupMemberDto.getAuthorGroup().getAuthorGroupName();
        this.authorGroup = authorGroupMemberDto.getAuthorGroup();
    }
    @JsonIgnore
    @Override
    public String getAuthority() {
        return this.groupName;
    }
}
