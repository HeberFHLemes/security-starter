package io.github.heberfhlemes.securitystarter.jwt;

import io.github.heberfhlemes.securitystarter.properties.JwtProperties;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;

import io.jsonwebtoken.JwtException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setup() {
        JwtProperties props = new JwtProperties();
        props.setSecret("example-of-long-jwt-secret-in-properties");
        props.setExpiration(Duration.ofMillis(100000));

        jwtTokenProvider = new JwtTokenProvider(props);
    }

    @Test
    void shouldGenerateExtractAndValidateJwtToken() {
        String token = jwtTokenProvider.generateToken("user_1");

        assertNotNull(token);

        String username = jwtTokenProvider.extractSubject(token);
        assertEquals("user_1", username);

        assertTrue(jwtTokenProvider.validateToken(token));
    }

    @Test
    void shouldExtractSubjectFromValidToken() {
        String token = jwtTokenProvider.generateToken("user1");
        assertEquals("user1", jwtTokenProvider.extractSubject(token));
    }

    @Test
    void extractSubjectShouldThrowForInvalidToken() {
        assertThrows(JwtException.class, () ->
                jwtTokenProvider.extractSubject("invalid.token")
        );
    }

    @Test
    void shouldRejectExpiredToken() throws InterruptedException {
        JwtProperties props = new JwtProperties();
        props.setSecret("example-of-long-jwt-secret-in-properties");
        props.setExpiration(Duration.ofMillis(1));
        JwtTokenProvider provider = new JwtTokenProvider(props);

        String token = provider.generateToken("user_1");
        Thread.sleep(100);

        assertFalse(provider.validateToken(token));
    }

    @Test
    void shouldRejectMalformedToken() {
        assertThrows(JwtException.class, () ->
                jwtTokenProvider.extractSubject("not.a.valid.token"));
    }

    @Test
    void shouldThrowExceptionWhenExtractingFromNullToken() {
        assertThrows(IllegalArgumentException.class, () ->
                jwtTokenProvider.extractSubject(null));
    }

    @Test
    void shouldThrowExceptionWhenExtractingFromEmptyToken() {
        assertThrows(IllegalArgumentException.class, () ->
                jwtTokenProvider.extractSubject(""));
    }

    @Test
    void shouldRejectNullToken() {
        assertFalse(jwtTokenProvider.validateToken(null));
    }

    @Test
    void shouldRejectEmptyToken() {
        assertFalse(jwtTokenProvider.validateToken(""));
    }

    @Test
    void shouldRejectTamperedToken() {
        String token = jwtTokenProvider.generateToken("user_1");

        String tamperedToken = token.substring(0, token.length() - 5) + "XXXXX";

        assertFalse(jwtTokenProvider.validateToken(tamperedToken));
    }

}
