package io.github.heberfhlemes.securitystarter.properties;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Configuration properties for JWT handling.
 *
 * <p>
 * This class maps configuration properties with prefix {@code securitystarter.jwt} and
 * provides values required for token generation and validation, including
 * the secret key and token expiration duration.
 * </p>
 *
 * <p>
 * <strong>Important:</strong> The secret must be non-empty and at least 32 bytes long
 * when encoded in UTF-8, which is the minimum required for HS256 signing.
 * </p>
 *
 * <p>
 * The token expiration can be configured using a {@link Duration} object.
 * By default, it is set to 720,000 milliseconds (12 minutes).
 * </p>
 *
 * <p>
 * This class is used internally by
 * {@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider}
 * (or any {@link io.github.heberfhlemes.securitystarter.application.ports.TokenProvider} implementation)
 * to configure token generation and validation behavior.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
@ConfigurationProperties(prefix = "securitystarter.jwt")
public class JwtProperties {

    /**
     * Secret key used for signing JWT tokens.
     * Must be at least 32 bytes for HS256.
     */
    private String secret;

    /**
     * Token expiration duration. Defaults to 12 minutes.
     */
    private Duration expiration = Duration.ofMillis(720000);

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Duration getExpiration() {
        return expiration;
    }

    public void setExpiration(Duration expiration) {
        this.expiration = expiration;
    }

    /**
     * Validates configuration properties after construction.
     *
     * @throws IllegalArgumentException if {@code secret} is empty or less than 32 bytes
     */
    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("JWT secret must not be empty");
        }

        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
        }
    }
}
