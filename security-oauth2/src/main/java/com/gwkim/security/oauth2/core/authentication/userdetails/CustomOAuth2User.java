package com.gwkim.security.oauth2.core.authentication.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.io.Serializable;
import java.util.*;

public class CustomOAuth2User implements OAuth2AuthenticatedPrincipal, Serializable {
    private static final long serialVersionUID = 720L;
    private Set<GrantedAuthority> authorities;
    private final Map<String, Object> attributes;
    private final String nameAttributeKey;

    public CustomOAuth2User(Map<String, Object> attributes, String nameAttributeKey) {
        this.authorities = Collections.emptySet();
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
    }

    public CustomOAuth2User(Set<GrantedAuthority> authorities, Map<String, Object> attributes, String nameAttributeKey) {
        this.authorities = authorities;
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
    }

    public String getName() {
        return this.getAttribute(this.nameAttributeKey).toString();
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    private Set<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet(Comparator.comparing(GrantedAuthority::getAuthority));
        sortedAuthorities.addAll(authorities);
        return sortedAuthorities;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj != null && this.getClass() == obj.getClass()) {
            DefaultOAuth2User that = (DefaultOAuth2User)obj;
            if (!this.getName().equals(that.getName())) {
                return false;
            } else {
                return !this.getAuthorities().equals(that.getAuthorities()) ? false : this.getAttributes().equals(that.getAttributes());
            }
        } else {
            return false;
        }
    }
}
