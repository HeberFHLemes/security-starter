package io.github.heberfhlemes.securitystarter.jwt;

import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtProperties;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setup() {
        JwtProperties props = new JwtProperties();
        props.setSecret("abcdefghiklong_secret_32bytes_min(^_^)");
        props.setExpiration(Duration.ofMillis(100000));

        jwtTokenProvider = new JwtTokenProvider(props);
    }

    @Test
    void shouldGenerateExtractAndValidateJwtToken() {
        String token = jwtTokenProvider.generateToken("user_1");

        assertNotNull(token);

        String username = jwtTokenProvider.extractSubject(token);
        assertEquals("user_1", username);

        assertTrue(jwtTokenProvider.validateToken(token, "user_1"));
    }

}
