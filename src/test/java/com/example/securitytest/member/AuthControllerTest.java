package com.example.securitytest.member;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.securitytest.security.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Collections;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@WebMvcTest(AuthController.class)
class AuthControllerTest {
    @MockBean
    private MemberService memberService;

    @MockBean
    private JwtProvider jwtProvider;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private final String secretKey = "SnNvbldlYlRva2VuQXV0aGVudGljYXRpb25XaXRoU3ByaW5nQm9vdFRlc3RQcm9qZWN0U2VjcmV0S2V5";

    private static final long EXPIRE_TIME = 1000 * 60 * 30;

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Member member = Member.builder()
        .username("user")
        .password(passwordEncoder.encode("1234"))
        .roles(Collections.singletonList("ROLE_USER"))
        .build();

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

    @Test
    void success_createToken() throws Exception {
        //given
        String token = generateToken(member, EXPIRE_TIME, secretKey);
        given(memberService.authenticate(anyString(), anyString()))
            .willReturn(member);
        given(jwtProvider.generateToken(anyString(), any()))
            .willReturn(token);

        //when
        MvcResult result = mockMvc.perform(post("/auth/signin")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                new Auth.SignIn(member.getUsername(),
                    member.getPassword())
            )))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();

        //then
        assertEquals(token, result.getResponse().getContentAsString());
    }

}