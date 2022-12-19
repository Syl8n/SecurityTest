package com.example.securitytest.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import com.example.securitytest.member.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
class JwtProviderTest {

    @Mock
    UserDetailsService userDetailsService;

    @InjectMocks
    JwtProvider jwtProvider;

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final String secretKey = "SnNvbldlYlRva2VuQXV0aGVudGljYXRpb25XaXRoU3ByaW5nQm9vdFRlc3RQcm9qZWN0U2VjcmV0S2V5";
    private final String invalidKey = "FJWOIFVNROVJQERFOOQWKLVHVIQOUJVNVNSKJDNVOQNVIQNVINKNVASJD";

    private static final long EXPIRE_TIME = 1000 * 60 * 30;
    private Member member;
    private UserDetails userDetails;

    private String generateToken(Member member, long time, String key){
        Claims claims = Jwts.claims().setSubject(member.getUsername());
        claims.put("roles", member.getRoles());
        Date now = new Date();
        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + time))
            .signWith(SignatureAlgorithm.HS512, key)
            .compact();
    }

    @BeforeEach
    void setUp() {
        member = Member.builder()
            .username("user")
            .password(passwordEncoder.encode("1234"))
            .roles(Collections.singletonList("ROLE_USER"))
            .build();

        userDetails = new User(member.getUsername(),
            member.getPassword(),
            member.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
    }

    @Test
    @DisplayName("토큰 유효성 검증 성공")
    void success_validateToken() {
        //given
        String token = generateToken(member, EXPIRE_TIME, secretKey);

        //when
        boolean result = jwtProvider.validateToken(token);

        //then
        assertTrue(result);
    }

    @Test
    @DisplayName("토큰 유효성 검증 실패 - 만료된 토큰")
    void fail_validateToken_expiredToken() {
        //given
        String token = generateToken(member, -EXPIRE_TIME, secretKey);

        //when
        Exception exception = assertThrows(BadCredentialsException.class, () ->
            jwtProvider.validateToken(token));

        //then
        assertEquals("만료된 토큰", exception.getMessage());
    }

    @Test
    @DisplayName("토큰 유효성 검증 실패 - 잘못된 비밀키")
    void fail_validateToken_invalidSignature() {
        //given
        String token = generateToken(member, EXPIRE_TIME, invalidKey);

        //when
        Exception exception = assertThrows(BadCredentialsException.class, () ->
            jwtProvider.validateToken(token));

        //then
        assertEquals("잘못된 비밀키", exception.getMessage());
    }

    @Test
    @DisplayName("인증 객체 생성 성공")
    void success_getAuthentication() {
        //given
        String token = generateToken(member, EXPIRE_TIME, secretKey);
        given(userDetailsService.loadUserByUsername(anyString()))
            .willReturn(userDetails);

        //when
        Authentication authentication = jwtProvider.getAuthentication(token);

        //then
        assertEquals(member.getUsername(), authentication.getName());
        assertEquals("", authentication.getCredentials());
        assertEquals(member.getRoles().toString(), authentication.getAuthorities().toString());
    }
}