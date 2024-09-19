package com.gwkim.security.basic.core.jwt.dto;

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
