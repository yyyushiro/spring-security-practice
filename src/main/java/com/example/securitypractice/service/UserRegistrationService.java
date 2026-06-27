package com.example.securitypractice.service;

import com.example.securitypractice.dto.RegisterForm;
import com.example.securitypractice.entity.User;
import com.example.securitypractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void register(RegisterForm form) {
        if (userRepository.existsByUsername(form.getUsername())) {
            throw new IllegalArgumentException("This username already used");
        }

        User user = User.builder()
                .username(form.getUsername())
                .password(passwordEncoder.encode(form.getPassword()))
                .role(form.getRole())
                .provider("LOCAL")
                .build();

        userRepository.save(user);
    }
}