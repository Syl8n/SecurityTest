package com.example.securitytest.member;

import com.example.securitytest.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final MemberService memberService;
    private final JwtProvider jwtProvider;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody Auth.SignUp request){
        return ResponseEntity.ok(memberService.register(
                    request.getUsername(), request.getPassword(), request.getRoles()
            ));
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody Auth.SignIn request){
        // 패스워드 검증
        Member member = memberService.authenticate(request.getUsername(), request.getPassword());
        // 토큰 생성 & 반환
        return ResponseEntity.ok(jwtProvider.generateToken(member.getUsername(),
                                                            member.getRoles()));
    }
}
