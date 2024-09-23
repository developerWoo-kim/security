package com.gwkim.security.oauth2.core.authentication;

import com.gwkim.security.oauth2.core.authentication.dto.OAuth2Type;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2User;
import com.gwkim.security.oauth2.core.authentication.userdetails.OAuth2UserInfo;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.CustomOAuth2UserService;
import com.gwkim.security.oauth2.core.filter.OAuth2JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
public class OAuth2AuthenticationProvider implements AuthenticationProvider {
    private final CustomOAuth2UserService oAuth2UserService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("OAuth2AuthenticationProvider ::::: ");
        Map<String, Object> principal = (Map<String, Object>) authentication.getPrincipal();
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfo.of(OAuth2Type.NAVER, principal);
        CustomOAuth2User customOAuth2User = oAuth2UserService.loadUserByUsername(oAuth2UserInfo);
        CustomOAuth2AuthenticationToken authenticationToken = new CustomOAuth2AuthenticationToken(customOAuth2User, null);
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomOAuth2AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
