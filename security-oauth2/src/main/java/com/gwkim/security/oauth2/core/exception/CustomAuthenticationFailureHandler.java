package com.gwkim.security.oauth2.core.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.response.SecurityErrorResponse;
import com.gwkim.security.oauth2.core.response.exception.AuthenticationExceptionTypes;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

/**
 * Spring Security - 로그인 실패 핸들러
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@Slf4j
@NoArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        AuthenticationExceptionTypes exceptionTypes = AuthenticationExceptionTypes.findOf(exception.getClass().getSimpleName());

        ObjectMapper om = new ObjectMapper();

        SecurityErrorResponse commonErrorResponse = SecurityErrorResponse.builder()
                .code(exceptionTypes.getCode())
                .message(exceptionTypes.getMessage())
                .path(request.getRequestURI())
                .build();

        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
