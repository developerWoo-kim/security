package com.gwkim.security.oauth2.core.response.exception;

import com.gwkim.security.oauth2.core.response.SecurityError;
import lombok.Getter;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
public enum JwtTokenExceptionTypes {
    MalformedJwtException(SecurityError.CMM_AUTH_TOKEN_MALFORMED),
    ExpiredJwtException(SecurityError.CMM_AUTH_TOKEN_EXPIRED),
    UnsupportedJwtException(SecurityError.CMM_AUTH_TOKEN_UNSUPPORTED),
    IllegalArgumentException(SecurityError.CMM_AUTH_TOKEN_ILLEGAL_ARGUMENT),
    AUTHENTICATION_FAIL_EXCEPTION(SecurityError.CMM_AUTH_FAIL),
    SignatureException(SecurityError.CMM_AUTH_TOKEN_ILLEGAL_ARGUMENT);

    private final SecurityError error;

    JwtTokenExceptionTypes(SecurityError error) {
        this.error = error;
    }

    private static final Map<String, JwtTokenExceptionTypes> descriptions = Collections
            .unmodifiableMap(Stream.of(values())
                    .collect(Collectors.toMap(JwtTokenExceptionTypes::name, Function.identity())));

    public static JwtTokenExceptionTypes findOf(String findValue) {
        return Optional.ofNullable(descriptions.get(findValue)).orElse(SignatureException);
    }
}
