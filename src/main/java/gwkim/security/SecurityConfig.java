package gwkim.security;

import gwkim.security.checker.CustomAuthenticationProvider;
import gwkim.security.checker.PreAccountStatusUserDetailsChecker;
import gwkim.security.handler.CustomAuthenticationFailureHandler;
import gwkim.security.handler.CustomAuthenticationSuccessHandler;
import gwkim.security.service.CustomUserDetailsService;
import gwkim.security.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;

/**
 * Spring Security Config
 *
 * @author kimgunwoo
 * @since 2023.10.11
 * @version 1.0
 */
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomUserDetailsService customUserDetailsService;
    private final MemberService memberService;

    @Bean
    public HttpFirewall defaultHttpFireWall() {
        return new DefaultHttpFirewall();
    }

    /**
     * 인증 실패 핸들러
     * @return HttpAuthenticationEntryPoint
     */
    @Bean
    public HttpAuthenticationEntryPoint authenticationEntryPoint() {
        HttpAuthenticationEntryPoint httpAuthenticationEntryPoint = new HttpAuthenticationEntryPoint();
        httpAuthenticationEntryPoint.setErrorURL("/author/unauthorized");
        return httpAuthenticationEntryPoint;
    }

    /**
     * 인가 거부 핸들러
     * @return HttpAccessDeniedHandler
     */
    @Bean
    public HttpAccessDeniedHandler accessDeniedHandler() {
        HttpAccessDeniedHandler httpAccessDeniedHandler = new HttpAccessDeniedHandler();
        httpAccessDeniedHandler.setErrorURL("/author/denied");
        return httpAccessDeniedHandler;
    }

    /**
     * 로그인 성공 핸들러
     * @return AuthenticationSuccessHandler
     */
    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(memberService);
    }

    /**
     * 로그인 실패 핸들러
     * @return AuthenticationFailureHandler
     */
    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    /**
     * 비밀번호 체크 전 로그인 가능한 상태 인지 확인하는 체커
     * CustomUserDetailsService를 틍해 사용자 정보를 가져온다.
     * @return UserDetailsChecker
     */
    @Bean
    public UserDetailsChecker preUserDetailsChecker() {
        return new PreAccountStatusUserDetailsChecker();
    }


    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(new MessageDigestPasswordEncoder("SHA-256"));
        provider.setPreAuthenticationChecks(preUserDetailsChecker());
        provider.setPostAuthenticationChecks(new UserDetailsChecker() {
            @Override
            public void check(UserDetails toCheck) {

            }
        });
        return provider;
    }

    @Override
    public void configure(WebSecurity web) {
        // 더블 슬래시(//) 허용
        web.httpFirewall(defaultHttpFireWall());
        // spring boot의 static resource 위치를 모두 ignoring
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        web.ignoring().mvcMatchers();
    }

    /**
     * spring-security 인증 규칙 정의
     * authorizeRequests() : http요청에 대한 인가 처리, permitAll로 설정된 uri를 제외하고는 authorizationChecker.check()에서 권한을 체크한다.
     * exceptionHandling() : 권한이 없는 사용자에 대한 예외 처리
     * formLogin()         : session-cookie 인증 방식의 로그인 처리
     *
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http
                .authorizeRequests()
                .antMatchers("/", "/index", "/login", "/login-error",
                        "/login_proc","/author/denied", "/author/unauthorized").permitAll()
                .anyRequest().access("@authorizationChecker.check(request, authentication)");

        // 권한 없는 사용자에 대한 예외 처리
        http
                .exceptionHandling()
                        .authenticationEntryPoint(authenticationEntryPoint())   // 인증
                        .accessDeniedHandler(accessDeniedHandler());            // 인가

        // 로그인 처리
        http
                .formLogin((formLogin) -> formLogin
                        .loginPage("/login")
                        .loginProcessingUrl("/login_proc")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(customAuthenticationSuccessHandler())                   // 로그인 성공 핸들러
                        .failureHandler(customAuthenticationFailureHandler())                   // 로그인 실패 핸들러
//                        .failureUrl("/login-error")  // 실패 시 URI

                );

        // 로그아웃 처리
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID", "remember-me")
                .invalidateHttpSession(true);
    }
}
