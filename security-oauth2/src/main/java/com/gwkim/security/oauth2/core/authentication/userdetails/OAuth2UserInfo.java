package com.gwkim.security.oauth2.core.authentication.userdetails;

import com.gwkim.security.oauth2.core.authentication.dto.OAuth2Type;
import lombok.Builder;

import java.util.Map;

@Builder
public record OAuth2UserInfo(
        String id,
        String name,
        String mobile,
        String clientType
) {
    public static OAuth2UserInfo of(OAuth2Type auth2Type, Map<String, Object> attributes) {
        return switch (auth2Type) {
            case NAVER -> ofNaver(attributes);
            case KAKAO -> ofKakao(attributes);
        };
    }

    private static OAuth2UserInfo ofNaver(Map<String, Object> attributes) {
        return OAuth2UserInfo.builder()
                .id((String) attributes.get("id"))
                .name((String) attributes.get("name"))
                .mobile((String) attributes.get("mobile"))
                .clientType(OAuth2Type.NAVER.toString())
                .build();
    }

    private static OAuth2UserInfo ofKakao(Map<String, Object> attributes) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");

        return OAuth2UserInfo.builder()
                .id((String) attributes.get("id"))
                .name((String) account.get("nickname"))
                .mobile((String) account.get("phone_number"))
                .clientType(OAuth2Type.KAKAO.toString())
                .build();
    }
}
