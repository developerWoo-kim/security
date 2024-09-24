package com.gwkim.security.oauth2.core.filter.jwt;

import com.gwkim.security.oauth2.core.filter.jwt.dto.AccessTokenDto;
import com.gwkim.security.oauth2.core.filter.jwt.dto.TokenDto;
import com.gwkim.security.oauth2.core.response.SecurityError;
import com.gwkim.security.oauth2.core.response.exception.JwtSecurityException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Getter
@Slf4j
@Component
public class JwtTokenProvider {
    public static final String BEARER_TYPE = "Bearer";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration-millis}")
    private long accessTokenExpirationMillis;

    @Getter
    @Value("${jwt.refresh-token-expiration-millis}")
    private long refreshTokenExpirationMillis;

    private Key key;

    // Bean 등록후 Key SecretKey HS256 decode
    @PostConstruct
    public void init() {
        String base64EncodedSecretKey = encodeBase64SecretKey(this.secretKey);
        this.key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);
    }

    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto generateTokenDto(String username) {
        // Refresh Token 생성
        Date refreshTokenExpiresIn = createTokenExpiration(refreshTokenExpirationMillis);
        String refreshToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(refreshTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        // Access Token 생성
        Date accessTokenExpiresIn = createTokenExpiration(accessTokenExpirationMillis);
        Map<String, Object> accessClaims = new HashMap<>();
        accessClaims.put("username", username);
        String accessToken = Jwts.builder()
                .setClaims(accessClaims)
                .setExpiration(accessTokenExpiresIn)
                .setIssuedAt(Calendar.getInstance().getTime())
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .authorizationType(AUTHORIZATION_HEADER)
                .accessToken(accessToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Access Token 갱신
     * @param username String
     * @return AccessTokenDto
     */
    public AccessTokenDto generateAccessTokenDto(String username) {
        Date accessTokenExpiresIn = createTokenExpiration(accessTokenExpirationMillis);
        Map<String, Object> accessClaims = new HashMap<>();
        accessClaims.put("username", username);
        String accessToken = Jwts.builder()
                .setClaims(accessClaims)
                .setSubject(username)
                .setExpiration(accessTokenExpiresIn)
                .setIssuedAt(Calendar.getInstance().getTime())
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return AccessTokenDto.builder()
                .grantType(BEARER_TYPE)
                .authorizationType(AUTHORIZATION_HEADER)
                .accessToken(accessToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .build();
    }

    /**
     * 토큰 만료 기간 생성
     * @param expirationMillisecond
     * @return
     */
    private Date createTokenExpiration(long expirationMillisecond) {
        Date date = new Date();
        return new Date(date.getTime() + expirationMillisecond);
    }

    /**
     * 토큰 검증
     * @param token String
     * @return boolean
     * @throws IOException
     */
    public boolean validateToken(String token) {
        if(!StringUtils.hasText(token)) {
            return false;
        }
        Claims claims = parseClaims(token);
        return claims.getExpiration().after(new Date());
    }

    /**
     * JWT 토큰을 복호화하여 토큰 정보를 반환
     * Token 복호화 및 예외 발생(토큰 만료, 시그니처 오류)시 Claims 객체가 안만들어짐.
     * @param token String
     * @return Claims
     */
    public Claims parseClaims(String token){
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(this.key).build()
                    .parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            throw new JwtSecurityException(SecurityError.CMM_AUTH_TOKEN_EXPIRED);
//            return e.getClaims();
        } catch (MalformedJwtException e) {
            System.out.println(e.getMessage());
//            throw new TokenException(INVALID_TOKEN);
            throw new JwtSecurityException(SecurityError.CMM_AUTH_FAIL);
        }
    }

    /**
     * Access Token Header 세팅
     * @param accessToken String
     * @param response HttpServletResponse
     */
    public void setAccessTokenHeader(String accessToken, HttpServletResponse response) {
        String headerValue = BEARER_PREFIX + accessToken;
        response.setHeader(AUTHORIZATION_HEADER, headerValue);
    }

    /**
     * Refresh Token Header 세팅
     * @param refreshToken String
     * @param response HttpServletResponse
     */
    public void setRefreshTokenHeader(String refreshToken, HttpServletResponse response) {
        response.setHeader(AUTHORIZATION_HEADER, refreshToken);
    }

    /**
     * Request Header 에서 Access Token 추출
     *
     * @param request HttpServletRequest
     * @return String
     */
    public String resolveAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        throw new JwtSecurityException(SecurityError.CMM_AUTH_FAIL);
    }

    /**
     * Request Header 에서 Refresh Token 정보를 추출
     * @param request HttpServletRequest
     * @return String
     */
    public String resolveRefreshToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }
}