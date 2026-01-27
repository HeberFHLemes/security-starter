package io.github.heberfhlemes.securitystarter.application.ports;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public interface JwtAuthenticationConverter {
    UsernamePasswordAuthenticationToken convert(String token, String subject);
}
