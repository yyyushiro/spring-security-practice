package com.example.securitypractice.api_key;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @Nonnull FilterChain filterChain) throws ServletException, IOException {

        String apiKey = request.getHeader("X-API-KEY");

        if (apiKey == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication unauthenticated = new ApiAuthenticationToken(apiKey);
            Authentication result = authenticationManager.authenticate(unauthenticated);
            SecurityContextHolder.getContext().setAuthentication(result);
        } catch (AuthenticationException e) {
            // ここでエラーを返すのではなく、後続にその処理は任せる。
            // つまり、AnonymousAuthenticationFilterがSecurityContextHolderが空っぽなことを検知してanonymousとしての権限を与え、
            // それを AuthorizationFilterが検知してエラーを出し、
            // そのエラーをExceptionTranslationFilterに処理してもらう。
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
