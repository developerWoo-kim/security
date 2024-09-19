package com.gwkim.security.basic.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.basic.core.jwt.JwtTokenProvider;
import com.gwkim.security.basic.core.jwt.dto.TokenDto;
import com.gwkim.security.basic.core.userdetails.CustomUserDetails;
import com.gwkim.security.basic.port.in.SecurityLoginDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 * JWT 기반 로그인 필터
 *
 * UsernamePasswordAuthenticationFilter를 상속 받아 커스텀하여 Jwt토큰을 응답
 *
 * session 방식에서 form 로그인 방식으로 클라이언트에서 /login 요청을 처리하는 UsernamePasswordAuthenticationFilter 커스텀 함
 * username과 password를 받아 JWT 토큰을 반환하도록 개발
 *
 * 이 필터는 시큐리티 Filter Chain 에 추가 되었습니다.
 *
 * @author kimgunwoo
 * @since 2023.11.14
 * @version 1.0v
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * login 요청을 하면 로그인 시도를 위해서 실행되는 함수
     *
     * @param request from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a
     * redirect as part of a multi-stage authentication process (such as OpenID).
     * @return Authentication
     * @throws AuthenticationException
     */
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. memberId, password 를 받아서
        // 2. 정상 인지 로그인 시도 -> authenticationManager 로 로그인 시도를 하면
        // 3. CustomUserDetailsService 의 loadUserByUsername() 실행
        // 4. CustomUserDetails 를 세션에 담고(세션에 담는 이유는 권한 관리르 위해서)
        // 5. JWT토큰을 만들어서 응답
        // ServletInputStream을 LoginDto 객체로 역직렬화
        ObjectMapper objectMapper = new ObjectMapper();
        SecurityLoginDto loginDto = objectMapper.readValue(request.getInputStream(), SecurityLoginDto.class);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        CustomUserDetails userDetails = (CustomUserDetails) authenticate.getPrincipal();

        // 비밀번호 체크 -> 할 필요가 없음 왜냐하면 AuthenticationManager에서 인증 작업을 진행하면 ProviderManager에서 비밀번호 체크를 하게 되어 있음.
//        if(!passwordEncoder.matches(loginDto.getPassword(), userDetails.getPassword())) {
//            this.logger.debug("Failed to authenticate since password does not match stored value");
//            throw new BadCredentialsException(this.messages
//                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
//        }

        return authenticate;
    }

    /**
     * 1. attemptAuthentication 실행 후 인증이 정상적으로 되었으면
     * 2. successfulAuthentication 메서드가 실행
     * 3. Jwt 토큰을 만들어서 request 요청한 사용자에게 Jwt 토큰을 응답
     *
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param chain FilterChain
     * @param authResult the object returned from the <tt>attemptAuthentication</tt>
     * method.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication : 인증 완료");
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(customUserDetails);

        jwtTokenProvider.setAccessTokenHeader(tokenDto.getAccessToken(), response);
        jwtTokenProvider.setRefreshTokenHeader(tokenDto.getRefreshToken(), response);

        ObjectMapper om = new ObjectMapper();
        String result = om.writeValueAsString(tokenDto);

        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(result);

        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }
}
