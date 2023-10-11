package gwkim.security;

import gwkim.security.checker.CustomAuthenticationProvider;
import gwkim.security.checker.PreAccountStatusUserDetailsChecker;
import gwkim.security.handler.LoginFailureHandler;
import gwkim.security.handler.LoginSuccessHandler;
import gwkim.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public HttpFirewall defaultHttpFireWall() {
        return new DefaultHttpFirewall();
    }

    @Bean
    public HttpAuthenticationEntryPoint authenticationEntryPoint() {
        HttpAuthenticationEntryPoint httpAuthenticationEntryPoint = new HttpAuthenticationEntryPoint();
        httpAuthenticationEntryPoint.setErrorURL("/author/unauthorized");
        return httpAuthenticationEntryPoint;
    }

    @Bean
    public HttpAccessDeniedHandler accessDeniedHandler() {
        HttpAccessDeniedHandler httpAccessDeniedHandler = new HttpAccessDeniedHandler();
        httpAccessDeniedHandler.setErrorURL("/author/denied");
        return httpAccessDeniedHandler;
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

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
     *
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
                        .successHandler(loginSuccessHandler())                   // 로그인 성공 핸들러
                        .failureHandler(loginFailureHandler())                   // 로그인 실패 핸들러
//                        .failureUrl("/login-error")  // 실패 시 URI
                        .defaultSuccessUrl("/")             // 성공 시 URI

                );
        // 로그아웃 처리
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID", "remember-me")
                .invalidateHttpSession(true);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("test001")
                .password("0000")
                .roles()
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
