package com.gwkim.security.oauth2.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gwkim.security.oauth2.core.authentication.dto.OAuth2LoginDto;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2AuthenticationToken;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2User;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    private final JwtTokenProvider jwtTokenProvider;

    public OAuth2JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public OAuth2JwtAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationManager authenticationManager1, JwtTokenProvider jwtTokenProvider) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.authenticationManager = authenticationManager1;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        OAuth2LoginDto loginDto = objectMapper.readValue(request.getInputStream(), OAuth2LoginDto.class);

        String token = loginDto.getAccessToken();
        String header = loginDto.getOauth2Type().getType() + " " + token;
        String apiURL = loginDto.getOauth2Type().getUrl();

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(loginDto.getOauth2Type().getHeader(), header);
        String responseBody = get(apiURL, requestHeaders);


        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "test001");
        CustomOAuth2User key = new CustomOAuth2User(attributes, "key");
        CustomOAuth2AuthenticationToken authenticationToken = new CustomOAuth2AuthenticationToken(key);
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);



        System.out.println(responseBody);
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {

    }

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
