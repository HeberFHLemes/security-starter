package io.github.heberfhlemes.securitystarter.application;

import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtService;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Application-level service that provides a simplified interface for generating
 * and validating JWT tokens on top of the lower-level {@link JwtService}.
 *
 * <p>This service does <strong>not</strong> authenticate users. It assumes that the
 * application has already verified user credentials and simply needs to issue
 * or validate JWT tokens for stateless authentication workflows.</p>
 *
 * Applications may provide their own implementation if they need
 * custom token workflows, but using this class is entirely optional.
 *
 * @author Héber F. H. Lemes
 * @since 1.0.0
 */
public final class JwtAuthenticationService {

    private final JwtService jwtService;

    /**
     * Creates a new {@code JwtAuthenticationService} with the given {@link JwtService}.
     *
     * @param jwtService the underlying JWT service used for token operations
     */
    public JwtAuthenticationService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Generates a JWT token for the given authenticated user.
     *
     * @param user the authenticated user's details
     * @return a signed JWT token as a String
     */
    public String generateToken(UserDetails user) {
        return jwtService.generateToken(user.getUsername());
    }

    /**
     * Validates a JWT token and checks whether it belongs to the given username.
     *
     * @param token the token to validate
     * @param username the expected username extracted from the token
     * @return {@code true} if the token is valid and matches the username, otherwise {@code false}
     */
    public boolean validateToken(String token, String username) {
        return jwtService.validateToken(token, username);
    }

}
