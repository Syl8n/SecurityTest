package com.example.securitytest.member;

import com.example.securitytest.member.Auth.SignIn;
import com.example.securitytest.member.Auth.SignUp;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException {

        Member member = memberRepository.findById(username)
            .orElseThrow(() -> new UsernameNotFoundException("회원 정보가 일치하지 않습니다."));

        // 이렇게 하지 않고 Member implements UserDetails를 하고 메소드 오버라이드를 해도 됨
        // UserDetails 또한 Interface이기에 그 구현체인 User 객체를 통해 사용자 정보를
        // 넘길 수 있다는 걸 보여주고 싶었음
        return new User(member.getUsername(), member.getPassword(),
            member.getRoles().stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
    }

    public Member register(String username, String password, List<String> roles) {
        if (memberRepository.existsByUsername(username)) {
            throw new RuntimeException("이미 존재하는 ID 입니다 -> " + username);
        }

        password = passwordEncoder.encode(password);

        return memberRepository.save(Member.builder()
            .username(username)
            .password(password)
            .roles(roles)
            .build());
    }

    public Member authenticate(String username, String password) {
        Member member = memberRepository.findById(username)
            .orElseThrow(() -> new RuntimeException("존재하지 않는 ID 입니다"));

        // 패스워드 비교를 할 때에는 인코딩 된 값을 2번째 인자로
        // 이유는 2번째 인자가 salt 자리이며, 여기에 인코딩 된 패스워드를 넣어줘야
        // 동일한 값으로 변환이 된다.
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }
        return member;
    }
}
