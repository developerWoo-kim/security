package com.gwkim.security.basic.core.exception;

import lombok.Getter;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.neoclue.adruck.global.utils.code.error.GlobalError.*;

@Getter
public enum AuthenticationExceptionTypes {
    BadCredentialsException(
            CMM_AUTH_BAD_CREDENTIALS.getCode(),
            CMM_AUTH_BAD_CREDENTIALS.getMessage()
    ),
    UsernameNotFoundException(
            CMM_AUTH_BAD_CREDENTIALS.getCode(),
            CMM_AUTH_BAD_CREDENTIALS.getMessage()
    ),
    AccountExpiredException(
            CMM_AUTH_ACCOUNT_EXPIRED.getCode(),
            CMM_AUTH_ACCOUNT_EXPIRED.getMessage()
    ),
    CredentialsExpiredException(
            CMM_AUTH_CREDENTIALS_EXPIRED.getCode(),
            CMM_AUTH_CREDENTIALS_EXPIRED.getMessage()
    ),
    DisabledException(
            CMM_AUTH_ACCOUNT_DISABLED.getCode(),
            CMM_AUTH_ACCOUNT_DISABLED.getMessage()
    ),
    LockedException(
            CMM_AUTH_ACCOUNT_LOCKED.getCode(),
            CMM_AUTH_ACCOUNT_LOCKED.getMessage()
    ),
    NoneException(
            CMM_SYSTEM_ERROR.getCode(),
            CMM_SYSTEM_ERROR.getMessage()
    );

    private String code;
    private String message;

    AuthenticationExceptionTypes(String code, String message) {
        this.code = code;
        this.message = message;
    }

    private static final Map<String, AuthenticationExceptionTypes> descriptions = Collections
            .unmodifiableMap(Stream.of(values())
                    .collect(Collectors.toMap(AuthenticationExceptionTypes::name, Function.identity())));

    public static AuthenticationExceptionTypes findOf(String findValue) {
        return Optional.ofNullable(descriptions.get(findValue)).orElse(NoneException);
    }
}
