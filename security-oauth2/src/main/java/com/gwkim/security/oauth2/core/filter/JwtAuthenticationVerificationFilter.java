package com.gwkim.security.oauth2.core.filter;

import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import com.gwkim.security.oauth2.core.response.exception.JwtSecurityException;
import com.gwkim.security.oauth2.core.response.utils.JwtResponseUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

public class JwtAuthenticationVerificationFilter extends BasicAuthenticationFilter {
    private final JwtTokenProvider jwtTokenProvider;
    public JwtAuthenticationVerificationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String accessToken = jwtTokenProvider.resolveAccessToken(request);
            // JWT 토큰을 복호화하여 토큰 정보를 반환
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String username = (String) claims.get("username");
            CustomOAuth2AuthenticationToken authenticationToken = new CustomOAuth2AuthenticationToken(username, null);

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            filterChain.doFilter(request, response);
        } catch (JwtSecurityException e) {
            JwtResponseUtil.sendJsonErrorResponse(request, response, e);
        }
    }
}
