package io.github.heberfhlemes.securitystarter.application.services;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.application.token.GeneratedToken;
import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Application-level service that provides a simplified interface for generating and
 * validating authentication tokens on top of the lower-level {@link TokenProvider}.
 *
 * <p>
 * This service does <strong>not</strong> authenticate users. It assumes that the
 * application has already verified user credentials and simply needs to issue
 * or validate tokens for stateless authentication workflows.
 * </p>
 *
 * <p>
 * This starter provides a JWT-based {@link TokenProvider} by default. Applications
 * may supply their own {@link TokenProvider} or choose not to use this service at all.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public final class TokenAuthenticationService {

    private final TokenProvider tokenProvider;

    /**
     * Creates a new {@link TokenAuthenticationService} with the given {@link TokenProvider}.
     *
     * @param tokenProvider the underlying token provider used for token operations
     */
    public TokenAuthenticationService(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Generates a token for the given authenticated user.
     *
     * @param user the authenticated user's details
     * @return a {@link GeneratedToken object}
     */
    public GeneratedToken generateToken(UserDetails user) {
        return tokenProvider.generateToken(user.getUsername());
    }

    /**
     * Validates a token and checks whether it belongs to the given subject.
     *
     * @param token the token to validate
     * @return {@code true} if the token is valid and matches the subject, otherwise {@code false}
     */
    public TokenValidationResult validate(String token) {
        return tokenProvider.validate(token);
    }

}
