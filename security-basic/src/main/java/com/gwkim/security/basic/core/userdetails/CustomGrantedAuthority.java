package com.gwkim.security.basic.core.userdetails;

import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = -51255679987025341L;
    private final String roleName;
    public CustomGrantedAuthority(String roleName) {
        this.roleName = roleName;
    }
    @Override
    public String getAuthority() {
        return this.roleName;
    }
}
