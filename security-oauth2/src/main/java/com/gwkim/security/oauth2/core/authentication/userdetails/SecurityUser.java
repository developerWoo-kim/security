package com.gwkim.security.oauth2.core.authentication.userdetails;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@NoArgsConstructor
public class SecurityUser {
    private String id;
    private String name;

    public SecurityUser(String id, String name) {
        this.id = id;
        this.name = name;
    }
}
