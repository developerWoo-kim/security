package com.gwkim.security.oauth2.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import com.gwkim.security.oauth2.core.response.SecurityErrorResponse;
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

public class JwtVerificationFilter extends BasicAuthenticationFilter {
    private final JwtTokenProvider jwtTokenProvider;
    public JwtVerificationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String accessToken = jwtTokenProvider.resolveAccessToken(request);
            // JWT 토큰을 복호화하여 토큰 정보를 반환
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
//            Collection<Map<String, String>> authoritiesMap = (Collection<Map<String, String>>) claims.get("authorities");
//
//            List<GrantedAuthority> authorities = authoritiesMap.stream()
//                    .map(authority -> new SimpleGrantedAuthority(authority.get("authority")))
//                    .collect(Collectors.toList());

            String username = (String) claims.get("username");
//            CustomUserDetails customUserDetails = CustomUserDetails.of(memberId, authorities);
            CustomOAuth2AuthenticationToken authenticationToken = new CustomOAuth2AuthenticationToken(username, null);

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            filterChain.doFilter(request, response);
        } catch (JwtSecurityException e) {
            JwtResponseUtil.sendJsonErrorResponse(request, response, e);
//            SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
//                    .code(e.getSecurityError().getCode())
//                    .message(e.getSecurityError().getMessage())
//                    .path(request.getRequestURI())
//                    .build();
////            CommonErrorResponseUtil.sendJsonErrorResponse(response, HttpStatus.UNAUTHORIZED, errorResponse);
//
//            ObjectMapper om = new ObjectMapper();
//            response.setCharacterEncoding("utf-8");
//            response.setStatus(HttpStatus.UNAUTHORIZED.value());
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            response.getWriter()
//                    .write(om.writeValueAsString(errorResponse));
        }
    }
}
