package com.example.securitytest.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private static final String KEY_ROLES = "roles";
    private static final long EXPIRE_TIME = 1000 * 60 * 30; // 30 mins

    private final UserDetailsService userDetailsService;

    @Value("{spring.jwt.secret}")
    private String secretKey;

    public String generateToken(String username, List<String> roles) {
        // Claims 란 JWT의 payload 부분에 들어가는 데이터 단위라고 보면 된다.
        // Map<String, Object>를 상속하고 있기 때문에 key, value 형식으로 값을 넣을 수 있다.
        Claims claims = Jwts.claims().setSubject(username); // username
        claims.put(KEY_ROLES, roles); // 권한

        // 토큰 생성 시간
        Date now = new Date();
        // 토큰 만료 시간
        Date expireDate = new Date(now.getTime() + EXPIRE_TIME);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(expireDate)
            // 사용할 암호화 알고리즘, 비밀키
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact();
    }

    // 토큰 유효성 확인
    public boolean validateToken(String token){
        if(!StringUtils.hasText(token)){
            return false;
        }
        Claims claims = getClaims(token);
        return !claims.getExpiration().before(new Date());
    }

    // 토큰 기반으로 Authentication 객체 생성
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUserName(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "",
            userDetails.getAuthorities());
    }

    // Claims에서 username 추출
    private String getUserName(String token) {
        return getClaims(token).getSubject();
    }

    // 토큰에서 Claims 추출
    private Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e){
            return e.getClaims();
        }
    }
}
