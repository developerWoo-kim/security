package com.gwkim.security.basic.core.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.basic.core.response.SecurityErrorResponse;
import com.gwkim.security.basic.core.response.exception.AuthenticationExceptionTypes;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        AuthenticationExceptionTypes exceptionTypes = AuthenticationExceptionTypes.findOf(authException.getClass().getSimpleName());

        ObjectMapper om = new ObjectMapper();

        SecurityErrorResponse commonErrorResponse = SecurityErrorResponse.builder()
                .code(exceptionTypes.getCode())
                .message(exceptionTypes.getMessage())
                .path(request.getRequestURI())
                .build();

        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
