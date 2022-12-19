package com.example.securitytest.member;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/admin")
    public ResponseEntity<?> testAdmin(){
        return ResponseEntity.ok("관리자용 API 접근 성공!");
    }

    @GetMapping("/user")
    public ResponseEntity<?> testUser(){
        return ResponseEntity.ok("유저용 API 접근 성공!");
    }
}
