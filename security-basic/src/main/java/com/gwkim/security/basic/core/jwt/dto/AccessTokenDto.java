package com.gwkim.security.basic.core.jwt.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Schema(description = "AccessToken 응답")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessTokenDto {
    @Schema(description = "header type")
    private String grantType;
    @Schema(description = "Bearer 고정")
    private String authorizationType;
    @Schema(description = "토큰")
    private String accessToken;
    @Schema(description = "토큰 만료 시간")
    private Long accessTokenExpiresIn;
}
