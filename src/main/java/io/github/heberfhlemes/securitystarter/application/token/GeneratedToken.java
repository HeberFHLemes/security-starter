package io.github.heberfhlemes.securitystarter.application.token;

import java.time.Instant;

/**
 * Represents a newly generated JWT and its temporal metadata.
 *
 * @param token     the serialized JWT
 * @param issuedAt  the instant the token was issued
 * @param expiresAt the instant the token expires
 * @author Héber F. H. Lemes
 * @since 0.3.0
 */
public record GeneratedToken(
        String token,
        Instant issuedAt,
        Instant expiresAt
) {
}
