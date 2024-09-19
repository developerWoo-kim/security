package com.gwkim.security.oauth2.core.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.response.SecurityErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

import static com.gwkim.security.oauth2.core.response.SecurityError.CMM_AUTH_ROLE_NOT_FOUND;


public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        ObjectMapper om = new ObjectMapper();

        SecurityErrorResponse commonErrorResponse = new SecurityErrorResponse(CMM_AUTH_ROLE_NOT_FOUND.getCode(), CMM_AUTH_ROLE_NOT_FOUND.getMessage(), request.getRequestURI());


        response.setCharacterEncoding("utf-8");
        response.setStatus(CMM_AUTH_ROLE_NOT_FOUND.getStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
