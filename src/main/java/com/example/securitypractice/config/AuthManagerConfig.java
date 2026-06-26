package com.example.securitypractice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@Configuration
public class AuthManagerConfig {

    /**
     * This method returns AuthenticationManager, which is responsible for authenticating the incoming login request.
     *
     * @param config gathers all AuthenticationProviders (i.e. DaoAuthenticationProvider). Necessary components like UserDetailsService and PasswordEncoder are already injected.
     * @return AuthenticationManager
     * @throws Exception unknown
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
