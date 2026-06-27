package com.example.securitypractice.service;

import com.example.securitypractice.entity.User;
import com.example.securitypractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        // This method gets userInfo from the resource server.
        // This sends another HTTP request to the server to get more information than sub or email.
        OidcUser oidcUser = super.loadUser(userRequest);

        String email = oidcUser.getEmail();

        User user = userRepository.findByUsername(email)
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .username(email)
                                .password("")
                                .role("USER")
                                .provider("GOOGLE")
                                .build()
                ));

        return new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }
}
