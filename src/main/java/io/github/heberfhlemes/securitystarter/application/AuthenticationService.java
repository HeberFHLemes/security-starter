package io.github.heberfhlemes.securitystarter.application;

import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtService;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Encapsulates the authentication logic,
 * exposing a simple interface for token generation and validation.
 */
public class AuthenticationService {

    private final JwtService jwtService;

    public AuthenticationService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Generates a JWT token for the given user (UserDetails).
     *
     * @param user the user details
     * @return a JWT token as a String
     */
    public String generateToken(UserDetails user) {
        return jwtService.generateToken(user.getUsername());
    }

    /**
     * Validates a JWT token against a given username.
     *
     * @param token the JWT token to validate
     * @param username the username to match against the token
     * @return true if the token is valid and matches the username, false otherwise
     */
    public Boolean validateToken(String token, String username) {
        return jwtService.validateToken(token, username);
    }

}
