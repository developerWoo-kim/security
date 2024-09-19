package com.gwkim.security.oauth2.core.response;

import com.gwkim.security.utils.response.GlobalErrorResponse;
import lombok.Builder;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class SecurityErrorResponse extends GlobalErrorResponse {
    public SecurityErrorResponse(String code, String message, String path) {
        super(code, message, path);
    }
}
