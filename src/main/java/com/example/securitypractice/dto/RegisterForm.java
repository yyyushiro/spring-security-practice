package com.example.securitypractice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterForm {
        @NotBlank
        private String username;

        @NotBlank
        @Size(min = 8)
        private String password;

        @NotBlank
        private String role;
}