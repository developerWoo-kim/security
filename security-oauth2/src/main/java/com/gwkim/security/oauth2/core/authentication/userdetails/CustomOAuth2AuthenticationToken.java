package com.gwkim.security.oauth2.core.authentication.userdetails;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;

public class CustomOAuth2AuthenticationToken extends AbstractAuthenticationToken {
    @Serial
    private static final long serialVersionUID = 720L;
    private final OAuth2User principal;

    public CustomOAuth2AuthenticationToken(OAuth2User principal) {
        super(authorities);
        Assert.notNull(principal, "principal cannot be null");
        this.principal = principal;
        this.setAuthenticated(true);
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public Object getCredentials() {
        return "";
    }

}
