package com.gwkim.security.basic.core.filter;

import com.gwkim.security.basic.core.exception.JwtTokenExceptionTypes;
import com.gwkim.security.basic.core.exception.custom.AccessTokenNotFound;
import com.gwkim.security.basic.core.jwt.JwtTokenProvider;
import com.gwkim.security.basic.core.userdetails.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * JWT 기반 권한, 인증 필터
 *
 * -> 시큐리티 filter chain 중 OncePerRequestFilter 와 BasicAuthenticationFilter가 있음.
 * -> 상위 클래스인 BasicAuthenticationFilter가 적절해 보여 사용
 * -> 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있음.
 * -> 만약 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탐
 *
 * @author kimgunwoo
 * @since 2023.11.14
 * @version 1.0v
 */
@Slf4j
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

            if(!jwtTokenProvider.validateToken(accessToken, request, response)) {
                throw new AccessTokenNotFound();
            }

            //                // JWT 토큰을 복호화하여 토큰 정보를 반환
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            Collection<Map<String, String>> authoritiesMap = (Collection<Map<String, String>>) claims.get("authorities");

            List<GrantedAuthority> authorities = authoritiesMap.stream()
                    .map(authority -> new SimpleGrantedAuthority(authority.get("authority")))
                    .collect(Collectors.toList());

            String memberId = (String) claims.get("memberId");
            CustomUserDetails customUserDetails = CustomUserDetails.of(memberId, authorities);

            log.info("# AuthMember.getRoles 권한 체크 = {}", customUserDetails.getAuthorities().toString());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    customUserDetails,
                    null,
                    customUserDetails.getAuthorities()
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        } catch (JwtException | AccessTokenNotFound e) {
            JwtTokenExceptionTypes jwtTokenExceptionTypes = JwtTokenExceptionTypes.findOf(e.getClass().getSimpleName());
            // TODO :: exception 처리 에러 응답 포맷에 맞게 처리 ㄱㄱ
//            GlobalErrorResponse errorResponse = GlobalErrorResponse.builder()
//                    .code(jwtTokenExceptionTypes.getError().getCode())
//                    .message(jwtTokenExceptionTypes.getError().getMessage())
//                    .path(request.getRequestURI())
//                    .build();
//            CommonErrorResponseUtil.sendJsonErrorResponse(response, HttpStatus.UNAUTHORIZED, errorResponse);
        }
    }
}
