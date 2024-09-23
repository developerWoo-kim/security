package com.gwkim.security.oauth2.domain;

public enum SocialTypeEnum {
    NAVER("네이버"),
    KAKAO("카카오"),
    ;

    private final String value;

    SocialTypeEnum(String value) {
        this.value = value;
    }
}
