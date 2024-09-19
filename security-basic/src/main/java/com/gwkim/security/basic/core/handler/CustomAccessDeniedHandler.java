package com.gwkim.security.basic.core.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neoclue.adruck.global.utils.code.error.GlobalErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

import static com.neoclue.adruck.global.utils.code.error.GlobalError.CMM_AUTH_ROLE_NOT_FOUND;


public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        ObjectMapper om = new ObjectMapper();

        GlobalErrorResponse commonErrorResponse = GlobalErrorResponse.builder()
                .code(CMM_AUTH_ROLE_NOT_FOUND.getCode())
                .message(CMM_AUTH_ROLE_NOT_FOUND.getMessage())
                .path(request.getRequestURI())
                .build();

        response.setCharacterEncoding("utf-8");
        response.setStatus(CMM_AUTH_ROLE_NOT_FOUND.getStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter()
                .write(om.writeValueAsString(commonErrorResponse));
    }
}
