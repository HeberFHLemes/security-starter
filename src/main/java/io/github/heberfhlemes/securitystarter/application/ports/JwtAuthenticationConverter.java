package io.github.heberfhlemes.securitystarter.application.ports;

import org.springframework.security.core.Authentication;

/**
 * Strategy interface responsible for converting a validated token and its
 * subject into a Spring Security {@link Authentication} instance.
 *
 * <p>This abstraction allows applications to customize how principals,
 * authorities, or additional details are resolved from a token.</p>
 *
 * @since 0.2.0
 */
public interface JwtAuthenticationConverter {
    /**
     * Converts a validated JWT token and its subject into a Spring Security
     * {@link Authentication} instance.
     *
     * <p>The returned authentication is expected to be fully authenticated
     * and suitable for storage in the {@link org.springframework.security.core.context.SecurityContext}.</p>
     *
     * @param token   the raw JWT token
     * @param subject the subject extracted from the token (usually the username)
     * @return an authenticated {@link Authentication} instance, or {@code null}
     *         if the token cannot be converted
     *
     * @since 0.2.0
     */
    Authentication convert(String token, String subject);
}
