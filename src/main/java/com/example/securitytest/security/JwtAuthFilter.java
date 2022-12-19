package com.example.securitytest.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

// 모든 Security filter는 Bean으로 등록되어 ContextLoaderListener에 의해 로드된다.
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    // JWT의 생성, 해독, 변환 등을 담당할 녀석
    private final JwtProvider jwtProvider;

    // 헤더 내부에서 JWT 용으로 사용 할 Key이다.
    // 보통 Authorization 이라고 붙인다.
    public static final String HEADER_KEY = "Authorization";

    // 인증 타입을 의미한다. JWT는 Bearer 토큰의 일종이라고 Spring security 3편에서 말했다.
    // 꼭 Bearer 라고 쓸 필요는 없긴 하다. 하지만 ABCDEF 따위 보다는 의미 있는 이름이 낫다.
    public static final String PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 토큰 부분을 분리
        String token = resolveTokenFromRequest(request);

        // 토큰 유효성 검증
        if(StringUtils.hasText(token) && jwtProvider.validateToken(token)){
            // Authentication 객체 받아오기
            Authentication auth = jwtProvider.getAuthentication(token);
            // SecurityContextHoler에 저장
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }

    private String resolveTokenFromRequest(HttpServletRequest request){
        // 헤더에서 토큰 부분을 분리
        String token = request.getHeader(HEADER_KEY);

        // 해당 키에 해당하는 헤더가 존재하고, 그 값이 Bearer로 시작한다면 (즉 JWT가 있다면)
        if(!ObjectUtils.isEmpty(token) && token.startsWith(PREFIX)) {
            // PREFIX 부분을 날리고 JWT만 token에 할당한다.
            return token.substring(PREFIX.length());
        }

        return null;
    }
}
