package gwkim.security.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import gwkim.security.domain.AuthorGroup;
import gwkim.security.domain.dto.AuthorGroupDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = -51255679987025341L;
    private final String groupName;

    @Getter
    private final AuthorGroupDto authorGroup;
    public CustomGrantedAuthority(AuthorGroupDto authorGroup) {
        this.groupName = authorGroup.getAuthorGroupName();
        this.authorGroup = authorGroup;
    }
    @JsonIgnore
    @Override
    public String getAuthority() {
        return this.groupName;
    }
}
