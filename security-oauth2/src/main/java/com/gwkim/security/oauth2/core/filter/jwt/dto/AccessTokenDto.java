package com.gwkim.security.oauth2.core.filter.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessTokenDto {

    private String grantType;
    private String authorizationType;
    private String accessToken;
    private Long accessTokenExpiresIn;
}
