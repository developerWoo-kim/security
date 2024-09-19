package com.gwkim.security.oauth2.core.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.response.SecurityErrorResponse;
import com.gwkim.security.oauth2.core.response.exception.AuthenticationExceptionTypes;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

import static com.gwkim.security.oauth2.core.response.SecurityError.CMM_AUTH_ROLE_NOT_FOUND;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        AuthenticationExceptionTypes exceptionTypes = AuthenticationExceptionTypes.findOf(authException.getClass().getSimpleName());

        ObjectMapper om = new ObjectMapper();

        SecurityErrorResponse commonErrorResponse = new SecurityErrorResponse(CMM_AUTH_ROLE_NOT_FOUND.getCode(), CMM_AUTH_ROLE_NOT_FOUND.getMessage(), request.getRequestURI());

        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
