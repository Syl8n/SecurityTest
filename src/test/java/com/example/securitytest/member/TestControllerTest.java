package com.example.securitytest.member;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TestControllerTest {

    @MockBean
    private MemberService memberService;

    @Autowired
    private MockMvc mockMvc;

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final String secretKey = "SnNvbldlYlRva2VuQXV0aGVudGljYXRpb25XaXRoU3ByaW5nQm9vdFRlc3RQcm9qZWN0U2VjcmV0S2V5";

    private static final long EXPIRE_TIME = 1000 * 60 * 30;
    private Member memberUser = Member.builder()
        .username("user")
        .password(passwordEncoder.encode("1234"))
        .roles(Collections.singletonList("ROLE_USER"))
        .build();
    private Member memberAdmin = Member.builder()
        .username("admin")
        .password(passwordEncoder.encode("1234"))
        .roles(Collections.singletonList("ROLE_ADMIN"))
        .build();;

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

    private UserDetails createUserDetails(Member member){
        return new User(member.getUsername(),
            member.getPassword(),
            member.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
    }

    @Test
    void success_accessUserApi() throws Exception {
        //given
        String token = generateToken(memberUser, EXPIRE_TIME, secretKey);
        given(memberService.loadUserByUsername(anyString()))
            .willReturn(createUserDetails(memberUser));

        //when
        //then
        mockMvc.perform(get("/user")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    void fail_accessUserApi_tokenNotFound() throws Exception {
        //given
        String token = generateToken(memberUser, EXPIRE_TIME, secretKey);
        given(memberService.loadUserByUsername(anyString()))
            .willReturn(createUserDetails(memberUser));

        //when
        //then
        mockMvc.perform(get("/user"))
            .andExpect(status().isForbidden());
    }

    @Test
    void success_accessAdminApi() throws Exception {
        //given
        String token = generateToken(memberAdmin, EXPIRE_TIME, secretKey);
        given(memberService.loadUserByUsername(anyString()))
            .willReturn(createUserDetails(memberAdmin));

        //when
        //then
        mockMvc.perform(get("/admin")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    void fail_accessAdminApi_authorityNotMatched() throws Exception {
        //given
        String token = generateToken(memberUser, EXPIRE_TIME, secretKey);
        given(memberService.loadUserByUsername(anyString()))
            .willReturn(createUserDetails(memberUser));

        //when
        //then
        mockMvc.perform(get("/admin")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

}