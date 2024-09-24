package com.gwkim.security.oauth2.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.authentication.dto.OAuth2LoginDto;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2User;
import com.gwkim.security.oauth2.core.authentication.userdetails.OAuth2UserInfo;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import com.gwkim.security.oauth2.core.filter.jwt.dto.TokenDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class OAuth2JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");
    private final AuthenticationManager authenticationManager;

    public OAuth2JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        OAuth2LoginDto loginDto = objectMapper.readValue(request.getInputStream(), OAuth2LoginDto.class);

        String token = loginDto.getAccessToken();
        String header = loginDto.getOauth2Type().getType() + " " + token;
//        String header = "";
        String apiURL = loginDto.getOauth2Type().getUrl();

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(loginDto.getOauth2Type().getHeader(), header);
        String responseBody = get(apiURL, requestHeaders);
        System.out.println(responseBody);

        Map<String, Object> responseBodyMap = objectMapper.readValue(responseBody, Map.class);
        Map<String, Object> result = (Map<String, Object>) responseBodyMap.get("response");

        CustomOAuth2AuthenticationToken authenticationToken = new CustomOAuth2AuthenticationToken(result);
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

        return authenticate;
    }

//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
//        System.out.println("successfulAuthentication ::::: ");
//        CustomOAuth2AuthenticationToken oAuth2UserInfo = (CustomOAuth2AuthenticationToken) auth;
//        CustomOAuth2User principal = (CustomOAuth2User) oAuth2UserInfo.getPrincipal();
//        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(principal.getUserInfo().id());
//
//        jwtTokenProvider.setAccessTokenHeader(tokenDto.getAccessToken(), response);
//        jwtTokenProvider.setRefreshTokenHeader(tokenDto.getRefreshToken(), response);
//
//        ObjectMapper om = new ObjectMapper();
//        String result = om.writeValueAsString(tokenDto);
//
//        response.setCharacterEncoding("utf-8");
//        response.setStatus(HttpStatus.OK.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.getWriter().write(result);
//
//        this.getSuccessHandler().onAuthenticationSuccess(request, response, auth);
//
//    }

    private static String get(String apiUrl, Map<String, String> requestHeaders){
        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod("GET");
            for(Map.Entry<String, String> header :requestHeaders.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { // 정상 호출
                return readBody(con.getInputStream());
            } else { // 에러 발생
                return readBody(con.getErrorStream());
            }
        } catch (IOException e) {
            throw new RuntimeException("API 요청과 응답 실패", e);
        } finally {
            con.disconnect();
        }
    }


    private static HttpURLConnection connect(String apiUrl){
        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection)url.openConnection();
        } catch (MalformedURLException e) {
            throw new RuntimeException("API URL이 잘못되었습니다. : " + apiUrl, e);
        } catch (IOException e) {
            throw new RuntimeException("연결이 실패했습니다. : " + apiUrl, e);
        }
    }


    private static String readBody(InputStream body){
        InputStreamReader streamReader = new InputStreamReader(body);

        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();

            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }

            return responseBody.toString();
        } catch (IOException e) {
            throw new RuntimeException("API 응답을 읽는데 실패했습니다.", e);
        }
    }
}
