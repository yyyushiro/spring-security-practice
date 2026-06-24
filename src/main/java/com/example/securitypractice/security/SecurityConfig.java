package com.example.securitypractice.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        var delegatingAuthenticationEntryPoint = delegatingAuthenticationEntryPoint();

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/login").permitAll()
                        .anyRequest().authenticated())

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(delegatingAuthenticationEntryPoint))

                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/hello", true)
                        .permitAll()
                )

                .httpBasic(Customizer.withDefaults())

                .logout(logout -> logout
                        .logoutSuccessUrl("/login")
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private DelegatingAuthenticationEntryPoint delegatingAuthenticationEntryPoint() {
        var entryPoints = new LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>();
        entryPoints.put(
                PathPatternRequestMatcher.withDefaults().matcher("/hello-form"),
                new LoginUrlAuthenticationEntryPoint("/login")
        );
        entryPoints.put(
                PathPatternRequestMatcher.withDefaults().matcher("/hello-basic"),
                new BasicAuthenticationEntryPoint()
        );
        return new DelegatingAuthenticationEntryPoint(entryPoints);
    }

}
