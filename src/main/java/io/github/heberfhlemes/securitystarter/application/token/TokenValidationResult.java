package io.github.heberfhlemes.securitystarter.application.token;

import java.time.Instant;

/**
 * Result of a JWT validation attempt.
 *
 * <p>Contains the validation status and, if valid,
 * the extracted subject and expiration timestamp.</p>
 *
 * @param valid     whether the token is valid
 * @param subject   the token subject (typically the user identifier), or {@code null} if invalid
 * @param expiresAt the token expiration instant, or {@code null} if invalid
 * @author Héber F. H. Lemes
 * @since 0.3.0
 */
public record TokenValidationResult(
        boolean valid,
        String subject,
        Instant expiresAt
) {
}
