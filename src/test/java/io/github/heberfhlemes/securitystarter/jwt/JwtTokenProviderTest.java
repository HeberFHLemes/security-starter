package io.github.heberfhlemes.securitystarter.jwt;

import io.github.heberfhlemes.securitystarter.application.token.GeneratedToken;
import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;
import io.github.heberfhlemes.securitystarter.properties.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setup() {
        JwtProperties props = new JwtProperties();
        props.setSecret("example-of-long-jwt-secret-in-properties");
        props.setExpiration(Duration.ofMillis(100_000));

        jwtTokenProvider = new JwtTokenProvider(props);
    }

    @Test
    void shouldGenerateAndValidateJwtToken() {
        GeneratedToken generated = jwtTokenProvider.generateToken("user_1");

        assertNotNull(generated.token());

        TokenValidationResult result =
                jwtTokenProvider.validate(generated.token());

        assertTrue(result.valid());
        assertEquals("user_1", result.subject());
        assertNotNull(result.expiresAt());
    }

    @Test
    void shouldRejectExpiredToken() throws InterruptedException {
        JwtProperties props = new JwtProperties();
        props.setSecret("example-of-long-jwt-secret-in-properties");
        props.setExpiration(Duration.ofMillis(1));

        JwtTokenProvider provider = new JwtTokenProvider(props);

        String token = provider.generateToken("user_1").token();
        Thread.sleep(50);

        TokenValidationResult result = provider.validate(token);

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
    }

    @Test
    void shouldRejectNullToken() {
        TokenValidationResult result = jwtTokenProvider.validate(null);

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
    }

    @Test
    void shouldRejectEmptyToken() {
        TokenValidationResult result = jwtTokenProvider.validate("");

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
    }

    @Test
    void shouldRejectTamperedToken() {
        String token = jwtTokenProvider.generateToken("user_1").token();

        String tamperedToken =
                token.substring(0, token.length() - 5) + "XXXXX";

        TokenValidationResult result =
                jwtTokenProvider.validate(tamperedToken);

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
    }

    @Test
    void shouldRejectTokenSignedWithDifferentSecret() {
        String token = jwtTokenProvider.generateToken("user_1").token();

        JwtProperties otherProps = new JwtProperties();
        otherProps.setSecret("another-very-long-secret-key-123456");
        otherProps.setExpiration(Duration.ofSeconds(60));

        JwtTokenProvider otherProvider =
                new JwtTokenProvider(otherProps);

        TokenValidationResult result =
                otherProvider.validate(token);

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
    }

    @Test
    void shouldReturnExpirationConsistentWithConfiguration() {
        Duration expiration = Duration.ofSeconds(60);

        Instant fixedNow = Instant.parse("2026-01-01T00:00:00Z");
        Clock fixedClock = Clock.fixed(fixedNow, ZoneOffset.UTC);

        JwtProperties props = new JwtProperties();
        props.setSecret("example-of-long-jwt-secret-in-properties");
        props.setExpiration(expiration);

        JwtTokenProvider provider = new JwtTokenProvider(props, fixedClock);

        String token = provider.generateToken("user_1").token();

        TokenValidationResult result = provider.validate(token);

        assertTrue(result.valid());
        assertNotNull(result.expiresAt());

        Instant expectedExpiration = fixedNow.plus(expiration);

        assertEquals(expectedExpiration, result.expiresAt());
    }
}
