package com.gwkim.security.basic.port.in;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class SecurityLoginDto {
    private String username;
    private String password;
}
