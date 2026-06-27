package com.example.securitypractice.api_key;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class ApiAuthenticationToken extends AbstractAuthenticationToken {

    private final UserDetails principal;

    private final String apiKey;

    public ApiAuthenticationToken(String apiKey) {
        super(null);
        this.principal = null;
        this.apiKey = apiKey;
    }

    public ApiAuthenticationToken(UserDetails principal, String apiKey,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.apiKey = apiKey;
        setAuthenticated(true);
    }

    /**
     * Before authentication succeeds, returns the resolved owner's identity as a {@link UserDetails}.
     * Before that point (i.e. right after extraction from the request), this may be {@code null}.
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * Returns the raw API key string that was used to authenticate this request.
     * Before authentication, this is the value extracted from the request header.
     * After successful authentication, this field is typically erased by {@link #eraseCredentials()}.
     */
    @Override
    public Object getCredentials() {
        return this.apiKey;
    }
}
