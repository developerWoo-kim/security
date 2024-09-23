package com.gwkim.security.oauth2.core.authentication.userdetails;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.*;

public class CustomOAuth2User implements CustomOAuth2AuthenticatedPrincipal, Serializable {
    private static final long serialVersionUID = 720L;
    private Set<GrantedAuthority> authorities;
    @Getter
    private final OAuth2UserInfo userInfo;

    public CustomOAuth2User(OAuth2UserInfo userInfo) {
        this.authorities = Collections.emptySet();
        this.userInfo = userInfo;
    }

    public CustomOAuth2User(Set<GrantedAuthority> authorities, OAuth2UserInfo userInfo) {
        this.authorities = authorities;
        this.userInfo = userInfo;
    }

    public String getName() {
        return "";
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }
}
