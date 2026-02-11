package io.github.heberfhlemes.securitystarter.application.ports;

import io.github.heberfhlemes.securitystarter.application.token.GeneratedToken;
import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;

/**
 * Application-level port for token-based authentication mechanisms.
 *
 * <p>Implementations are responsible for generating and validating
 * authentication tokens (e.g. JWT, opaque tokens, API tokens).</p>
 *
 * <p>This interface does <strong>not</strong> perform user authentication.
 * It assumes that the subject has already been authenticated and focuses
 * solely on token lifecycle and validation concerns.</p>
 *
 * <p>Implementations must be stateless and thread-safe.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public interface TokenProvider {

    /**
     * Generates a new authentication token for the given subject.
     *
     * @param subject the identifier to associate with the token
     * @return a generated token with metadata
     */
    GeneratedToken generateToken(String subject);

    /**
     * Validates the given token and extracts its metadata.
     *
     * <p>This method performs integrity and expiration checks.
     * It does not perform application-specific authorization checks.</p>
     *
     * @param token the token to validate
     * @return the validation result containing status and extracted data
     */
    TokenValidationResult validate(String token);
}
