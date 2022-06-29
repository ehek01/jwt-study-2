package io.getarrays.jwtstudy2.config;

import io.getarrays.jwtstudy2.filter.CustomAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder; // TODO 얘는 UserServiceImpl 를 참조한다.... ㄹㅇ 중요 대박사건임.

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web
                .ignoring()
                .antMatchers("/h2-console/**", "/favicon.ico"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Basic AuthenticationManager and UserDetailService Create
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);

        AuthenticationManager authenticationManager
                = authenticationManagerBuilder.build();

        // 해당 개체를 사용하여 URL 을 변경할 수 있으며, 사용자를 지정할 수 있는 몇가지 다른 항목도 있습니다.
        // 그래서 여기로 가서 필터를 설정하고 URL 을 처리할 수 있습니다.
        /**
         *  원래는 UsernamePasswordAuthenticationFilter 에서 /login 이 기본으로 구현되어 있지만,
         *  다른 주소로 해주고 싶으면 이런방식을 사용할 수 있습니다.
         */
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager);
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(STATELESS) // 세션 설정 끄기

                // 권한 설정
                .and()
                .authorizeHttpRequests()
                .antMatchers("/api/login/**").permitAll()
                .antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER")
                .antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN") // 사용자를 저장하기 위해서는 관리자 권한이 필요.
                .anyRequest().authenticated() // 모든경로는 인증을 받아야 한다.

                // 필터랑 password encoder 등 이것저것 추가?
                .and()
                .authenticationManager(authenticationManager)
                .addFilter(customAuthenticationFilter);

        return http.build();
    }
}