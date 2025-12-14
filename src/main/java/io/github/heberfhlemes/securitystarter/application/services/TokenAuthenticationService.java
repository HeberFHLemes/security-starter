package io.github.heberfhlemes.securitystarter.application.services;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Application-level service that provides a simplified interface for generating and
 * validating authentication tokens (JWT by default) on top of the lower-level
 * {@link TokenProvider}.
 *
 * <p>This service does <strong>not</strong> authenticate users. It assumes that the
 * application has already verified user credentials and simply needs to issue
 * or validate tokens for stateless authentication workflows.</p>
 *
 * Applications may provide their own implementation if they need
 * custom token workflows, but using this class is entirely optional.
 *
 * @author Héber F. H. Lemes
 * @since 1.0.0
 */
public final class TokenAuthenticationService {

    private final TokenProvider tokenProvider;

    /**
     * Creates a new {@code TokenAuthenticationService} with the given {@link TokenProvider}.
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
     * @return a signed token as a String
     */
    public String generateToken(UserDetails user) {
        return tokenProvider.generateToken(user.getUsername());
    }

    /**
     * Validates a token and checks whether it belongs to the given username.
     *
     * @param token the token to validate
     * @param username the expected username extracted from the token
     * @return {@code true} if the token is valid and matches the username, otherwise {@code false}
     */
    public boolean validateToken(String token, String username) {
        return tokenProvider.validateToken(token, username);
    }

}
