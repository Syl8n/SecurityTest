package com.example.securitytest.member;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public class Auth {

    @Getter
    @Setter
    @AllArgsConstructor
    public static class SignUp{
        private String username;
        private String password;
        private List<String> roles;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class SignIn{
        private String username;
        private String password;
    }

}
