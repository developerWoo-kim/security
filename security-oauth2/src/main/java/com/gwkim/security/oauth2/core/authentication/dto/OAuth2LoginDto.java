package com.gwkim.security.oauth2.core.authentication.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class OAuth2LoginDto {
    private OAuth2Type oauth2Type;
    private String accessToken;
}
