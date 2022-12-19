package com.example.securitytest.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Value("{spring.jwt.secret}")
    private String secretKey;

    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {

        Claims claims;

        try {
//            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(((JwtAuthenticationToken) authentication).getJsonWebToken()).getBody();
        } catch (SignatureException signatureException) {
            throw new BadCredentialsException("잘못된 비밀키", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new BadCredentialsException("만료된 토큰", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new BadCredentialsException("변조 및 위조된 토큰", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new BadCredentialsException("잘못된 입력값", illegalArgumentException);
        }
//        return new JwtAuthenticationToken(claims.getSubject(), "", createGrantedAuthorities(claims));

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
