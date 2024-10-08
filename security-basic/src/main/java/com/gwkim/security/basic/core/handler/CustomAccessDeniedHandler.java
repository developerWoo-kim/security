package com.gwkim.security.basic.core.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.basic.core.response.SecurityError;
import com.gwkim.security.basic.core.response.SecurityErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;


public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        ObjectMapper om = new ObjectMapper();

        SecurityErrorResponse commonErrorResponse = SecurityErrorResponse.builder()
                .code(SecurityError.CMM_AUTH_ROLE_NOT_FOUND.getCode())
                .message(SecurityError.CMM_AUTH_ROLE_NOT_FOUND.getMessage())
                .path(request.getRequestURI())
                .build();

        response.setCharacterEncoding("utf-8");
        response.setStatus(SecurityError.CMM_AUTH_ROLE_NOT_FOUND.getStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
