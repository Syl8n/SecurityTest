package com.example.securitytest.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";
    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Basic 방식도 헤더에 토큰을 넣어 보내기 때문에 혼동이 없도록 비활성화 해버리기
            .httpBasic().disable()
            // csrf 체크를 하는 부분인데, jwt 방식은 세션을 사용하지 않기 때문에 끄는 것이 좋다
            .csrf().disable()
            // Spring Security에서 세션을 만들지 않고, 있어도 사용하지 않는다는 설정
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // 각 요청에 대한 권한 설정
            .authorizeRequests()
            // 아래 요청들은 인증이 없어도 허용
            .antMatchers("/**/signup", "/**/signin").permitAll()
            // 아래 요청은 관리자 권한이 있어야 허용
            .antMatchers("/admin").hasRole(ROLE_ADMIN)
            // 아래 요청은 유저 or 관리자 권한이 있어야 허용
            .antMatchers("/user").hasAnyRole(ROLE_USER, ROLE_ADMIN)
            .and()
            // 커스텀 필터를 ID/PW 기반으로 인증하는 기본 필터 앞에 넣어서 먼저 인증을 시도하게 함
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
