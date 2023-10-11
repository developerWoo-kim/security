package gwkim.security.custom;

import com.fasterxml.jackson.annotation.JsonIgnore;
import gwkim.security.domain.AuthorGroup;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = -51255679987025341L;
    private final String groupName;

    @Getter
    private final AuthorGroup authorGroup;
    public CustomGrantedAuthority(AuthorGroup authorGroup) {
        this.groupName = authorGroup.getAuthorGroupName();
        this.authorGroup = authorGroup;
    }
    @JsonIgnore
    @Override
    public String getAuthority() {
        return this.groupName;
    }
}
