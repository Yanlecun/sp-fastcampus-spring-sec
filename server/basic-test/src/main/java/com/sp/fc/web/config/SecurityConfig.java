package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// 접근 체크 모듈 작동시키기
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true) // 권한 체크 모듈
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //yml에는 한 명만 추가할 수 있기 때문에 여기에다 추가하면 된다.

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // user에 대한 authencation을 추가하면, application.yml에 등록한 사용자는 접근x
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                    .username("user2")
                        .password(passwordEncoder().encode("1111"))
                        .roles("USER"))
                .withUser(User.builder()
                    .username("admin")
                        .password(passwordEncoder().encode("1111"))
                        .roles("ADMIN"));
    }

    // 패스워드 인코더를 빈으로 만들자
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //모든 페이지는 기본적으로 막고 있음, 매인 홈페이지는 접근하도록 하고싶은데 어떻게 해야할까?


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.antMatcher("/**") ; // 모든 접근에서 필터 적용하기

        http.authorizeRequests((requests) ->
                // 어떤 요청이든 인증받은 상태에서 접근해라 라고 설정되어 있음
                //requests.anyRequest().authenticated());

                // 이러한 접근은 모든 사람에게 접근을 허용하도록 하기
                requests.antMatchers("/").permitAll().anyRequest().authenticated());
        http.formLogin();
        http.httpBasic();

        http.headers().disable()
                .csrf().disable()
                .requestCache().disable();  // 필터 사용하지 않겠다고 알림

    }
}
