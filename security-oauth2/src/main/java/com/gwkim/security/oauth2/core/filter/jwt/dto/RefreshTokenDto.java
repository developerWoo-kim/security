package com.gwkim.security.oauth2.core.filter.jwt.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RefreshTokenDto {
    private String grantType;
    private String authorizationType;
    private String refreshToken;
    private Long refreshTokenExpiresIn;
}
