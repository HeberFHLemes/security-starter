package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Configuration properties for JWT.
 *
 * <p>Requires a non-empty secret (minimum 32 bytes for HS256) and allows
 * setting a token expiration (default = 720000ms, 12 minutes).</p>
 */
@ConfigurationProperties(prefix = "jjwt")
public class JwtProperties {

    private String secret;

    // DEFAULT = 12 min
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
