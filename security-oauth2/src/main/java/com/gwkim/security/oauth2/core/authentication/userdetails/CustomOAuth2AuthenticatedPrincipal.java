package com.gwkim.security.oauth2.core.authentication.userdetails;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface CustomOAuth2AuthenticatedPrincipal extends AuthenticatedPrincipal {
    Collection<? extends GrantedAuthority> getAuthorities();
}
