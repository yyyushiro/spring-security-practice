package com.example.securitypractice.controller;

import com.example.securitypractice.dto.LoginRequest;
import com.example.securitypractice.dto.TokenResponse;
import com.example.securitypractice.repository.RefreshTokenRepository;
import com.example.securitypractice.service.DatabaseUserDetailsService;
import com.example.securitypractice.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class JwtAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final DatabaseUserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        // You can rely on AuthenticationManager because the login flow is the same as form/basic login.
        // You want to use authentication to issue an access token later.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        String accessToken = jwtService.generateAccessToken(authentication);
        String refreshToken = jwtService.generateRefreshToken(authentication.getName());

        response.addHeader(HttpHeaders.SET_COOKIE, buildRefreshCookie(refreshToken).toString());
        return ResponseEntity.ok(new TokenResponse(accessToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@CookieValue("refresh-token") String refreshTokenValue) {
        var stored = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new BadCredentialsException("invalid refresh token"));

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.deleteByToken(refreshTokenValue);
            throw new BadCredentialsException("expired refresh token");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(stored.getUsername());
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        return ResponseEntity.ok(new TokenResponse(jwtService.generateAccessToken(authentication)));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue("refresh-token") String refreshTokenValue) {
        refreshTokenRepository.deleteByToken(refreshTokenValue);
        return ResponseEntity.noContent().build();
    }

    private ResponseCookie buildRefreshCookie(String value) {
        return ResponseCookie.from("refresh-token", value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(Duration.ofDays(14))
                .build();
    }
}
