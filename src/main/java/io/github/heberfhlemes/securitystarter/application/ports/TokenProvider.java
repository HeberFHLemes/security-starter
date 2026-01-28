package io.github.heberfhlemes.securitystarter.application.ports;

/**
 * Application-level port for token-based authentication mechanisms.
 *
 * <p>
 * Implementations of this interface are responsible for generating,
 * validating, and extracting information from authentication tokens
 * (e.g. JWT, opaque tokens, API tokens).
 * </p>
 *
 * <p>
 * This interface does <strong>not</strong> perform user authentication.
 * It assumes that the subject has already been authenticated by the
 * application and focuses only on token lifecycle and validation concerns.
 * </p>
 *
 * <p>
 * Implementations must be stateless and thread-safe.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public interface TokenProvider {

    /**
     * Generates a new authentication token for the given subject.
     *
     * @param subject the subject to associate with the token
     *                (e.g. username, user id)
     * @return a generated authentication token
     */
    String generateToken(String subject);

    /**
     * Validates an authentication token.
     *
     * <p>
     * This method performs full token validation, including integrity
     * and expiration checks, depending on the token implementation.
     * It does not perform any application-specific checks such as
     * subject or role validation.
     * </p>
     *
     * @param token the token to validate
     * @return {@code true} if the token is valid and can be safely used;
     *         {@code false} otherwise
     */
    boolean validateToken(String token);

    /**
     * Extracts the subject associated with the given token.
     *
     * <p>
     * This method assumes the token is valid. Callers should invoke
     * {@link #validateToken(String)} before calling this method.
     * </p>
     *
     * @param token the authentication token
     * @return the subject contained in the token
     * @throws RuntimeException if the token is invalid, expired,
     *                          or cannot be parsed
     */
    String extractSubject(String token);

}
