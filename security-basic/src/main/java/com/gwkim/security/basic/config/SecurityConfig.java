package com.gwkim.security.basic.config;

import com.gwkim.security.basic.core.filter.JwtAuthenticationFilter;
import com.gwkim.security.basic.core.filter.JwtVerificationFilter;
import com.gwkim.security.basic.core.handler.CustomAccessDeniedHandler;
import com.gwkim.security.basic.core.handler.CustomAuthenticationEntryPoint;
import com.gwkim.security.basic.core.handler.CustomAuthenticationFailureHandler;
import com.gwkim.security.basic.core.handler.CustomAuthenticationSuccessHandler;
import com.gwkim.security.basic.core.jwt.JwtTokenProvider;
import com.gwkim.security.basic.core.userdetails.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;


/**
 * jwt token 기반 스프링 시큐리티 설정
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();                 // -> 스프링에서 권장하고 있음 sha256 보다 안전 하다
//        return new MessageDigestPasswordEncoder("SHA-256"); -> 한국 인터넷 진흥원에서 권장함
    }

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }


    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.addExposedHeader("Authorization");
        configuration.addExposedHeader("Refresh");
        configuration.addAllowedHeader("*");
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(
                "/swagger-ui/**", "/swagger-resources/**", "/v2/api-docs", "/v3/api-docs",
                "/api/v1/auth/token", "/auth/reissue", "/error", "/api/v1/file/test", "/api/v1/log",
                "/api/v1/user/join", "/api/v1/user/password", "/api/v1/user/by-phoneNum/**",
                "/api/v1/user/id-duple-check/**","/api/v1/code/detail/**", "/api/v1/notification",
                "/api/v1/sms/cert/**", "/api/server/check",
                "/api/v1/vehicle-owner",
                "/files/**", "/api/v1/dummy-insert"
//                "/api/**"
        );
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // security 6.1 이전
//        http
//                .headers().frameOptions().sameOrigin()
//                .and()
//                .csrf().disable()
//                .cors().configurationSource(corsConfigurationSource())// CrossOrigin(인증X), 시리큐리 필터에 등록(인증O)
//                .and()
//                .formLogin().disable()
//                .httpBasic().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 권한 없는 사용자에 대한 예외 처리
//        http
//                .exceptionHandling()
//                .authenticationEntryPoint(new CustomAuthenticationEntryPoint()) // 인증
//                .accessDeniedHandler(new CustomAccessDeniedHandler());          // 인가

        //  security 6.1 이후
        http
                .headers(httpSecurityHeadersConfigurer ->
                        httpSecurityHeadersConfigurer.frameOptions(
                                HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource())
                ) // CrossOrigin(인증X), 시리큐리 필터에 등록(인증O)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // 권한 없는 사용자에 대한 예외 처리
        http
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint())   // 인증
                        .accessDeniedHandler(new CustomAccessDeniedHandler())             // 인가
                );

//        http
//                .authorizeRequests()
//                .anyRequest().access("@authorizationChecker.check(request, authentication)");


//        http
//                .apply(new CustomFilterConfigurer());

        http
                .with(new CustomFilterConfigurer(), CustomFilterConfigurer::build);

        return http.build();
    }

    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenProvider);

            jwtAuthenticationFilter.setFilterProcessesUrl("/auth/login");
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new CustomAuthenticationFailureHandler());

            http
                    // 시큐리티 필터 체인이 모든 필터의 우선 순위를 가진다
                    .addFilter(jwtAuthenticationFilter)
                    .addFilter(new JwtVerificationFilter(authenticationManager, jwtTokenProvider));

            super.configure(http);

        }

        public HttpSecurity build() {
            return getBuilder();
        }
    }
}
