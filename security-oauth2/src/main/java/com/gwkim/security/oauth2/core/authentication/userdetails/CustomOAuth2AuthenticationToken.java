package com.gwkim.security.oauth2.core.authentication.userdetails;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serial;
import java.util.Collection;

@Getter
public class CustomOAuth2AuthenticationToken extends AbstractAuthenticationToken {
    @Serial
    private static final long serialVersionUID = 720L;
    private final Object principal;

    public CustomOAuth2AuthenticationToken(Object principal) {
        super(null);
        this.principal = principal;
        this.setAuthenticated(false);
    }

    public CustomOAuth2AuthenticationToken(Object principal, Collection<GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.setAuthenticated(true);
    }

    public Object getCredentials() {
        return "";
    }

}
