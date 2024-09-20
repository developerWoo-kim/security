package com.gwkim.security.oauth2.core.authentication;

import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.CustomOAuth2UserService;
import com.gwkim.security.oauth2.core.filter.OAuth2JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
public class OAuth2AuthenticationProvider implements AuthenticationProvider {
    private final CustomOAuth2UserService oAuth2UserService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("OAuth2AuthenticationProvider ::::: ");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomOAuth2AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
