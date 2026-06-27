package com.example.securitypractice.controller;

import com.example.securitypractice.entity.ApiKey;
import com.example.securitypractice.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.UUID;

@Controller
@RequestMapping("/manage-keys")
@RequiredArgsConstructor
public class ApiKeyManagementController {

    private final ApiKeyRepository apiKeyRepository;

    @GetMapping
    public String page(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "manage-keys";
    }

    @PostMapping("/issue")
    public String issue(Authentication authentication, Model model) {
        String rawKey = UUID.randomUUID().toString();

        ApiKey apiKey = ApiKey.builder()
                .key(rawKey)
                .owner(authentication.getName())
                .role("USER")
                .build();
        apiKeyRepository.save(apiKey);

        model.addAttribute("username", authentication.getName());
        model.addAttribute("issuedKey", rawKey);
        return "manage-keys";
    }
}
