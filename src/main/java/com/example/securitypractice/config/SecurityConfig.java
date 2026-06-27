package com.example.securitypractice.config;

import com.example.securitypractice.Handler.Oauth2JwtSuccessHandler;
import com.example.securitypractice.api_key.ApiAuthenticationProvider;
import com.example.securitypractice.api_key.ApiKeyAuthenticationFilter;
import com.example.securitypractice.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.sql.DataSource;
import java.security.Security;
import java.util.LinkedHashMap;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOidcUserService customOidcUserService;
    private final Oauth2JwtSuccessHandler oauth2JwtSuccessHandler;

    @Bean
    @Order(0)
    public SecurityFilterChain apiKeyChain(HttpSecurity http, AuthenticationManager apiKeyAuthenticationManager)
        throws Exception {
        var filter = new ApiKeyAuthenticationFilter(apiKeyAuthenticationManager);

        http
                .securityMatcher("/api-key/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

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

    @Bean
    @Order(3)
    public SecurityFilterChain googleOauthChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/oauth2-test/**", "/login/oauth2/**", "/oauth2/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(customOidcUserService))
                        .successHandler(oauth2JwtSuccessHandler));

        return http.build();
    }


    /**
     * This chain is for form / basic login with Remember me.
     */
    @Bean
    @Order(4)
    public SecurityFilterChain webFilterChain(HttpSecurity http, RememberMeServices rememberMeServices) throws Exception {

        var delegatingAuthenticationEntryPoint = delegatingAuthenticationEntryPoint();

        http
                .securityMatcher("/hello-form", "/hello-basic", "/login", "/register", "/manage-keys", "/manage-keys/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/login").permitAll()
                        .anyRequest().authenticated())

                // We set the custom entry point before form or basic sets it.
                // This is because we can set only a single entry point, so
                // either of form or basic can set it without delegating entry point
                // which has two entry points inside it.
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(delegatingAuthenticationEntryPoint))

                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/manage-keys", true)
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

    /**
     * Explicitly registering this provider keeps the global AuthenticationManager
     * (used by Form Login and JWT login) working with username/password,
     * even though ApiAuthenticationProvider is also registered as an AuthenticationProvider bean.
     * Without this, Spring Security's auto-configuration sees exactly one AuthenticationProvider bean
     * (ApiAuthenticationProvider) and uses only that one, skipping the automatic DaoAuthenticationProvider
     * setup that would otherwise be built from UserDetailsService + PasswordEncoder.
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
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

    @Bean
    public AuthenticationManager apiKeyAuthenticationManager(ApiAuthenticationProvider provider) {
        return new ProviderManager(provider);
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
