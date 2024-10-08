package com.gwkim.security.oauth2.core.config;

import com.gwkim.security.oauth2.core.authentication.OAuth2AuthenticationProvider;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.CustomOAuth2UserService;
import com.gwkim.security.oauth2.core.exception.CustomAccessDeniedHandler;
import com.gwkim.security.oauth2.core.exception.CustomAuthenticationEntryPoint;
import com.gwkim.security.oauth2.core.exception.CustomAuthenticationFailureHandler;
import com.gwkim.security.oauth2.core.exception.CustomAuthenticationSuccessHandler;
import com.gwkim.security.oauth2.core.filter.JwtAuthenticationVerificationFilter;
import com.gwkim.security.oauth2.core.filter.OAuth2JwtAuthenticationFilter;
import com.gwkim.security.oauth2.core.filter.jwt.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtTokenProvider tokenProvider;
    private final CustomOAuth2UserService oAuth2UserService;


    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.addExposedHeader("Authorization");
        configuration.addAllowedHeader("*");
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        OAuth2AuthenticationProvider provider = new OAuth2AuthenticationProvider(oAuth2UserService);
//        provider.setPreAuthenticationChecks(preUserDetailsChecker());
        return provider;
    }

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring().requestMatchers(
//                "/example"
//        );
//    }


    /**
     * 권한 체크
     * @param authentication
     * @param context
     * @return
     */
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();

        Authentication auth = authentication.get();
//        if(!(auth.getPrincipal() instanceof CustomUserDetails)) {
//            return new AuthorizationDecision(false);
//        };
//        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
//
//        // 마스터 권한의 계정은 프리패스
//        if(userDetails.hasRole("ROLE_MASTER")) {
//            return new AuthorizationDecision(true);
//        }


        String requestURI = request.getRequestURI();

        if(requestURI.equals("/admin/auth/manage-list")) {
            // TODO: 6/28/24 Auth Check 해야함
        }

        return new AuthorizationDecision(true);
    }


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 1. 기본 설정
        http
                .headers(httpSecurityHeadersConfigurer ->
                        httpSecurityHeadersConfigurer.frameOptions(
                                HeadersConfigurer.FrameOptionsConfig::disable)
                ) // X-Frame-Option 비활성화
                .csrf(AbstractHttpConfigurer::disable) // csrf 비활성화
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()) // CrossOrigin(인증X)
                )
                .httpBasic(AbstractHttpConfigurer::disable) // 기본 인증 로그인 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 기본 폼 로그인 비활성화
                .logout(AbstractHttpConfigurer::disable) // 기본 로그아웃 비활성화
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 안함
                );

        http.authorizeHttpRequests(authorizeRequest -> authorizeRequest
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/assets/**"
                        ).permitAll()
//                .anyRequest().authenticated()
                        .anyRequest().access(this::check)
//                        .access(this::test)

        );

        // 2. 필터 설정 (custom jwt filter)
//        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
//        http
//                .addFilterBefore(new OAuth2JwtAuthenticationFilter(authenticationManager, tokenProvider), UsernamePasswordAuthenticationFilter.class);

        // 2. 인증(authentication) & 인가(authorization) 예외 핸들링
        http
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint())   // 인증
                        .accessDeniedHandler(new CustomAccessDeniedHandler())             // 인가
                );

        http
                .with(new CustomFilterConfigurer(), CustomFilterConfigurer::build);

        return http.build();
    }

    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            OAuth2JwtAuthenticationFilter jwtAuthenticationFilter = new OAuth2JwtAuthenticationFilter(authenticationManager);
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler(tokenProvider));
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new CustomAuthenticationFailureHandler());

            http
                    // 시큐리티 필터 체인이 모든 필터의 우선 순위를 가진다
                    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                    .addFilter(new JwtAuthenticationVerificationFilter(authenticationManager, tokenProvider));

            super.configure(http);

        }

        public HttpSecurity build() {
            return getBuilder();
        }
    }
}
