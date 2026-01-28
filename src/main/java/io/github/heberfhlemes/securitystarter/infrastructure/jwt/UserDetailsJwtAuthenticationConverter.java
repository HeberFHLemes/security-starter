package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Default JWT authentication converter that resolves user details using a
 * {@link UserDetailsService}.
 *
 * <p>This implementation produces an authenticated
 * {@link UsernamePasswordAuthenticationToken}.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.2.0
 */
public class UserDetailsJwtAuthenticationConverter implements JwtAuthenticationConverter {

    private final UserDetailsService userDetailsService;

    /**
     * Constructs a new converter using the given {@link UserDetailsService}.
     *
     * @param userDetailsService service used to load user details from the JWT subject
     */
    public UserDetailsJwtAuthenticationConverter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication convert(String token, String subject) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }
}
