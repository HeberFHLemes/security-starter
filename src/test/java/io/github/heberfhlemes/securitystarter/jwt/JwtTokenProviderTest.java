/*
 * Copyright 2025 Héber F. H. Lemes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
    void shouldGenerateAndValidateJwtTokenWithCustomClaims() {
        GeneratedToken generated = jwtTokenProvider
                .generateToken("user_1", builder -> builder.issuer("myapp"));

        assertNotNull(generated.token());

        TokenValidationResult result = jwtTokenProvider.validate(generated.token());

        assertTrue(result.valid());
        assertEquals("user_1", result.subject());
    }

    @Test
    void shouldRejectJwtTokenWithIncorrectIssuer() {
        final String issuer = "myapp";

        JwtProperties otherProps = new JwtProperties();
        otherProps.setSecret("another-very-long-secret-key-123456");
        otherProps.setIssuer(issuer);

        JwtTokenProvider customProvider = new JwtTokenProvider(otherProps);

        GeneratedToken generated = customProvider
                .generateToken("user_1", builder -> builder.issuer("notissuer"));

        assertNotNull(generated.token());

        TokenValidationResult result =
                customProvider.validate(generated.token());

        assertFalse(result.valid());
        assertNull(result.subject());
        assertNull(result.expiresAt());
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
