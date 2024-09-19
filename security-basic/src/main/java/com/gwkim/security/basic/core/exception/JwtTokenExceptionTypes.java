package com.gwkim.security.basic.core.exception;

import com.neoclue.adruck.global.utils.code.error.GlobalError;
import lombok.Getter;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
public enum JwtTokenExceptionTypes {
    MalformedJwtException(GlobalError.CMM_AUTH_TOKEN_MALFORMED),
    ExpiredJwtException(GlobalError.CMM_AUTH_TOKEN_EXPIRED),
    UnsupportedJwtException(GlobalError.CMM_AUTH_TOKEN_UNSUPPORTED),
    IllegalArgumentException(GlobalError.CMM_AUTH_TOKEN_ILLEGAL_ARGUMENT),
    SignatureException(GlobalError.CMM_AUTH_TOKEN_ILLEGAL_ARGUMENT);

    private final GlobalError error;

    JwtTokenExceptionTypes(GlobalError error) {
        this.error = error;
    }

    private static final Map<String, JwtTokenExceptionTypes> descriptions = Collections
            .unmodifiableMap(Stream.of(values())
                    .collect(Collectors.toMap(JwtTokenExceptionTypes::name, Function.identity())));

    public static JwtTokenExceptionTypes findOf(String findValue) {
        return Optional.ofNullable(descriptions.get(findValue)).orElse(SignatureException);
    }
}
