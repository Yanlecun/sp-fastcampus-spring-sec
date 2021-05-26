package com.sp.fc.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @RequestMapping("/")
    public String index() {
        return "홈페이지";
    }

    // /auth로 접근하면 authehtication에 대한 정보를 볼 수 있다.
    @RequestMapping("/auth")
    public Authentication auth() {
        return SecurityContextHolder.getContext()
                .getAuthentication();
    }


    // 사이트의 개인 정보에 해당하는 리소스 시뮬레이션
    @PreAuthorize("hasAnyAuthority('ROLE_USER')") //페이지에 접근하려는 사람들의 접근권한 체크
    @RequestMapping("/user")
    public SecurityMessage user() {
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("User 정보 ")
                .build();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/admin")
    public SecurityMessage admin() {
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("Admin 정보 ")
                .build();
    }

    // user1,1111로 로그인 , 셋 다 접근 가능한데, 정보를 막아야함

}
