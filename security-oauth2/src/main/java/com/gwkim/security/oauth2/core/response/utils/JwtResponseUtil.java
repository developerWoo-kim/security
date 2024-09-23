package com.gwkim.security.oauth2.core.response.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.response.SecurityErrorResponse;
import com.gwkim.security.oauth2.core.response.exception.JwtSecurityException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;

public class JwtResponseUtil {

    public static void sendJsonErrorResponse(HttpServletRequest req, HttpServletResponse resp, JwtSecurityException e) throws IOException {
        SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
                .code(e.getSecurityError().getCode())
                .message(e.getSecurityError().getMessage())
                .path(req.getRequestURI())
                .build();

        ObjectMapper om = new ObjectMapper();
        resp.setCharacterEncoding("utf-8");
        resp.setStatus(e.getSecurityError().getStatus().value());
        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
        resp.getWriter()
                .write(om.writeValueAsString(errorResponse));
    }
}
