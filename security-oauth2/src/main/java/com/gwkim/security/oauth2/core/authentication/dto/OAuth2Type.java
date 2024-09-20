package com.gwkim.security.oauth2.core.authentication.dto;

import lombok.Getter;

@Getter
public enum OAuth2Type {
    NAVER("Authorization", "Bearer", "https://openapi.naver.com/v1/nid/me"),
    KAKAO("Authorization", "Bearer", ""),
    ;

    private final String header;
    private final String type;
    private final String url;

     OAuth2Type(String header, String type, String url) {
        this.header = header;
        this.type = type;
        this.url = url;
    }
}
