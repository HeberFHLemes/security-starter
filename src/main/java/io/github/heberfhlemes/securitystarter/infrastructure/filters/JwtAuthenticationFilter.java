package io.github.heberfhlemes.securitystarter.infrastructure.filters;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT authentication filter that extracts and validates JWT tokens from incoming HTTP requests.
 *
 * <p>
 * This filter intercepts requests, looks for the "Authorization" header with a Bearer token,
 * and if a valid token is present, it sets the corresponding {@link UsernamePasswordAuthenticationToken}
 * into the {@link SecurityContextHolder} for Spring Security.
 * </p>
 *
 * <p>
 * This filter relies on a {@link TokenProvider} to handle token parsing and validation, and a
 * {@link UserDetailsService} to load user details from the subject extracted from the token.
 * </p>
 *
 * <p>
 * <strong>Important:</strong> This filter does not authenticate credentials;
 * it only validates tokens for stateless authentication workflows.
 * Applications must provide their own {@link UserDetailsService} implementation.
 * </p>
 *
 * <p>Thread-safety: This class is stateless and safe for use across multiple requests.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationConverter authenticationConverter;

    /**
     * Constructs a new JwtAuthenticationFilter with the given dependencies.
     *
     * @param tokenProvider the token provider used for parsing and validating tokens
     * @param authenticationConverter JwtAuthenticationConverter implementation that provides
     */
    public JwtAuthenticationFilter(
            TokenProvider tokenProvider,
            JwtAuthenticationConverter authenticationConverter) {
        this.tokenProvider = tokenProvider;
        this.authenticationConverter = authenticationConverter;
    }

    /**
     * Processes an incoming HTTP request to extract and validate a JWT token.
     *
     * <p>If the "Authorization" header contains a Bearer token, this method extracts the subject,
     * loads user details, validates the token, and sets the {@link SecurityContextHolder} with
     * an authenticated {@link UsernamePasswordAuthenticationToken} if valid.</p>
     *
     * <p>Exceptions during token parsing or validation are logged and do not interrupt the filter chain.</p>
     *
     * @param request the incoming HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain to pass control to the next filter
     * @throws ServletException if an error occurs in the filter processing
     * @throws IOException if an I/O error occurs during processing
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7); // remove "Bearer "

        try {
            final String subject = tokenProvider.extractSubject(token);

            if (subject == null || SecurityContextHolder.getContext().getAuthentication() != null) {
                filterChain.doFilter(request, response);
                return;
            }
            if (!tokenProvider.validateToken(token, subject)) {
                filterChain.doFilter(request, response);
                return;
            }

            UsernamePasswordAuthenticationToken authToken = authenticationConverter.convert(token, subject);
            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);

        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("JWT token validation failed");
        } catch (Exception e) {
            logger.error("Unexpected error while processing JWT token", e);
        }

        filterChain.doFilter(request, response);
    }
}
