package com.example.securitypractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.sql.DataSource;
import java.util.LinkedHashMap;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    /**
     * This chain is for the APIs authenticated by JWT.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain authChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/auth/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }


    /**
     * This chain is for form / basic login with Remember me.
     */
    @Bean
    @Order(3)
    public SecurityFilterChain webFilterChain(HttpSecurity http, RememberMeServices rememberMeServices) throws Exception {

        var delegatingAuthenticationEntryPoint = delegatingAuthenticationEntryPoint();

        http
                .securityMatcher("/hello-form", "/hello-basic", "/login", "/register")
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

                .rememberMe(remember -> remember.rememberMeServices(rememberMeServices))

                .logout(logout -> logout
                        .logoutSuccessUrl("/login")
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Bean
    RememberMeServices rememberMeServices(UserDetailsService userDetailsService, PersistentTokenRepository persistentTokenRepository) {
        return new PersistentTokenBasedRememberMeServices("myKey", userDetailsService, persistentTokenRepository);
    }

    /**
     * DelegatingAuthenticationEntryPoint is set as an authenticationEntryPoint,
     * and delegates to actual entry points according to the request path.
     * We use this because we cannot set multiple entry points.
     *
     * @return DelegatingAuthenticationEntryPoint for form login and basic login.
     */
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
