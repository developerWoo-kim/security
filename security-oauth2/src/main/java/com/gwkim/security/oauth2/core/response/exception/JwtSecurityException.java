package com.gwkim.security.oauth2.core.response.exception;

import com.gwkim.security.oauth2.core.response.SecurityError;
import lombok.Getter;

@Getter
public class JwtSecurityException extends RuntimeException{
    private final SecurityError securityError;

    public JwtSecurityException(SecurityError securityError) {
        super();
        this.securityError = securityError;
    }
}
