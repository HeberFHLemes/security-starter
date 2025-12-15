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
 * application and focuses only on token lifecycle concerns.
 * </p>
 *
 * <p>
 * Implementations must be stateless and thread-safe.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 1.0.0
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
     * Validates the given token and checks whether it is associated
     * with the expected subject.
     *
     * <p>
     * Implementations should validate token integrity, expiration,
     * and subject consistency.
     * </p>
     *
     * @param token the token to validate
     * @param subject the expected subject contained in the token
     * @return {@code true} if the token is valid and matches the subject;
     *         {@code false} otherwise
     */
    boolean validateToken(String token, String subject);

    /**
     * Extracts the subject associated with the given token.
     *
     * @param token the authentication token
     * @return the subject contained in the token
     * @throws RuntimeException if the token is invalid or cannot be parsed
     */
    String extractSubject(String token);

}
