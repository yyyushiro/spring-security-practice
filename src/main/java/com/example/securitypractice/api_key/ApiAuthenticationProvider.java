package com.example.securitypractice.api_key;


import com.example.securitypractice.entity.ApiKey;
import com.example.securitypractice.repository.ApiKeyRepository;
import com.example.securitypractice.service.DatabaseUserDetailsService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ApiAuthenticationProvider implements AuthenticationProvider {

    private final DatabaseUserDetailsService databaseUserDetailsService;
    private final ApiKeyRepository apiKeyRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // verify the apiKey
        ApiAuthenticationToken apiAuthenticationToken = (ApiAuthenticationToken) authentication;
        ApiKey apiKey = apiKeyRepository.findByKey((String) apiAuthenticationToken.getCredentials())
                .orElseThrow(() -> new EntityNotFoundException("The given API key not found"));

        // if exists, get UserDetails and return ApiAuthenticationToken
        UserDetails userDetails = databaseUserDetailsService.loadUserByUsername(apiKey.getOwner());

        return new ApiAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
