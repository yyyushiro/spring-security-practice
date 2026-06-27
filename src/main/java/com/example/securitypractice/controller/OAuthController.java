package com.example.securitypractice.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
@RestController
public class OAuthController {
    @GetMapping("/oauth2-test/me")
    public Object me(@AuthenticationPrincipal OAuth2User principal) {
        return principal.getAttributes();
    }
}
