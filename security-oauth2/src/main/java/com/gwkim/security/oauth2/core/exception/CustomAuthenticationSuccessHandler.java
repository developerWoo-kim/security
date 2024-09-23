package com.gwkim.security.oauth2.core.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2User;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import com.gwkim.security.oauth2.core.filter.jwt.dto.TokenDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;


/**
 * 로그인 성공 핸들러
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.debug("로그인 성공 : >>>>");
        CustomOAuth2AuthenticationToken oAuth2UserInfo = (CustomOAuth2AuthenticationToken) authentication;
        CustomOAuth2User principal = (CustomOAuth2User) oAuth2UserInfo.getPrincipal();
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(principal.getUserInfo().id());

        jwtTokenProvider.setAccessTokenHeader(tokenDto.getAccessToken(), response);
        jwtTokenProvider.setRefreshTokenHeader(tokenDto.getRefreshToken(), response);

        ObjectMapper om = new ObjectMapper();
        String result = om.writeValueAsString(tokenDto);

        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(result);
    }
}
