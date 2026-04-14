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
package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.application.token.GeneratedToken;
import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;
import io.github.heberfhlemes.securitystarter.properties.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.Nullable;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.function.Consumer;

/**
 * JWT-based implementation of {@link TokenProvider}.
 *
 * <p>
 * This implementation is responsible for generating and validating
 * JSON Web Tokens (JWT) using an HMAC signing key derived from
 * {@link JwtProperties}.
 * </p>
 *
 * <p>
 * The {@code subject} claim represents the principal identifier
 * (typically a username or user ID).
 * </p>
 *
 * <p>
 * This class is stateless and thread-safe. All configuration is provided
 * at construction time, and no mutable shared state is maintained.
 * </p>
 *
 * <p>
 * A {@link Clock} is used internally for time-based operations,
 * allowing deterministic behavior in tests and full control over
 * token issuance and expiration validation.
 * </p>
 *
 * <p>
 * <strong>Note:</strong> This class does not perform credential authentication.
 * It assumes that the caller has already authenticated the user and
 * only needs to issue or validate tokens for stateless authentication flows.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public class JwtTokenProvider implements TokenProvider {

    private final JwtProperties properties;
    private final SecretKey signingKey;
    private final Clock clock;

    /**
     * Creates a new {@code JwtTokenProvider} using the system UTC clock.
     *
     * @param properties JWT configuration properties (secret and expiration)
     */
    public JwtTokenProvider(JwtProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /**
     * Creates a new {@code JwtTokenProvider} with a custom {@link Clock}.
     *
     * @param properties JWT configuration properties (secret and expiration)
     * @param clock      clock used for issuance and expiration validation
     */
    public JwtTokenProvider(JwtProperties properties, Clock clock) {
        this.properties = properties;

        byte[] keyBytes = properties.getSecret().getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);

        this.clock = clock;
    }

    /**
     * Generates a signed JWT token for the given subject.
     *
     * @param subject the principal identifier to store in the JWT {@code sub} claim
     * @return a {@link GeneratedToken} containing the token and its temporal metadata
     */
    @Override
    public GeneratedToken generateToken(String subject) {
        return generateToken(subject, builder -> {
        });
    }

    /**
     * Generates a signed JWT token for the given subject.
     *
     * <p>Examples:</p>
     * <ul>
     *   <li>
     *     Token with basic claims:
     *     <pre>{@code
     * generateToken("my-token-subject");
     *     }</pre>
     *   </li>
     *   <li>
     *     Token with additional claims:
     *     <pre>{@code
     * generateToken("my-token-subject", builder ->
     *     builder.claim("role", "ADMIN")
     * );
     *     }</pre>
     *   </li>
     * </ul>
     *
     * @param subject    the principal identifier stored in the {@code sub} claim
     * @param customizer a callback that allows adding custom claims or headers
     *                   to the JWT before it is signed (may be {@code null})
     * @return a {@link GeneratedToken} containing the token and its metadata
     */
    public GeneratedToken generateToken(String subject, @Nullable Consumer<JwtBuilder> customizer) {

        Instant now = clock.instant();
        Instant expiration = now.plus(properties.getExpiration());

        JwtBuilder builder = Jwts.builder()
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(signingKey);

        String issuer = properties.getIssuer();
        if (issuer != null && !issuer.isBlank()) {
            builder.issuer(issuer);
        }

        if (customizer != null) {
            customizer.accept(builder);
        }

        String token = builder.compact();

        return new GeneratedToken(token, now, expiration);
    }

    /**
     * Validates the provided JWT token.
     *
     * <p>
     * Validation includes:
     * </p>
     * <ul>
     *   <li>Signature verification</li>
     *   <li>Structural integrity verification</li>
     *   <li>Expiration validation</li>
     * </ul>
     *
     * <p>
     * If validation fails for any reason (malformed, expired, invalid signature),
     * a {@link TokenValidationResult} with {@code valid=false} is returned.
     * </p>
     *
     * @param token the JWT token to validate
     * @return a {@link TokenValidationResult} describing the validation outcome
     */
    @Override
    public TokenValidationResult validate(String token) {

        if (token == null || token.isBlank()) {
            return new TokenValidationResult(false, null, null);
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .clock(() -> Date.from(clock.instant()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String expectedIssuer = properties.getIssuer();
            if (expectedIssuer != null && !expectedIssuer.isBlank()) {
                if (!expectedIssuer.equals(claims.getIssuer())) {
                    return new TokenValidationResult(false, null, null);
                }
            }

            String subject = claims.getSubject();

            if (subject == null || subject.isBlank()) {
                return new TokenValidationResult(false, null, null);
            }

            Instant expiresAt = claims.getExpiration().toInstant();

            return new TokenValidationResult(true, subject, expiresAt);

        } catch (JwtException | IllegalArgumentException e) {
            return new TokenValidationResult(false, null, null);
        }
    }
}
