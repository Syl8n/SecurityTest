package com.example.securitytest.member;

import java.util.List;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Member {
    @Id
    private String username;
    private String password;
    // List가 MySql에 저장 불가능하므로 컨버터를 이용
    // 객체 -> DB 일 때는 [a, b] -> "a,b"
    // DB -> 객체 일 때는 "a,b" -> [a, b]
    // 컨버터 없이 @ElementCollection을 사용 할 수도 있음. 그 경우엔 DB 내 테이블이 분리
    @Convert(converter = MemberRoleConverter.class)
    private List<String> roles;
}
