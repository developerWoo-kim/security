package com.gwkim.security.oauth2.core.authentication.userdetails;

import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public interface CustomOAuth2AuthenticatedPrincipal extends AuthenticatedPrincipal {
    @Nullable
    default Object getAttribute(String name) {
        return this.getAttributes().get(name);
    }

    Map<String, Object> getAttributes();

    Collection<? extends GrantedAuthority> getAuthorities();
}
