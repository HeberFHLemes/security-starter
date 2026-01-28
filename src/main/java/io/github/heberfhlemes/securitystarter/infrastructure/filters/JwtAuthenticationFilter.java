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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT authentication filter that extracts and validates JWT tokens from incoming HTTP requests.
 *
 * <p>
 * This filter intercepts requests, looks for the {@code Authorization} header with a Bearer token,
 * and, if a valid token is present, delegates the creation of a Spring Security
 * {@link Authentication} instance to a {@link JwtAuthenticationConverter}.
 * </p>
 *
 * <p>
 * The filter itself is responsible only for:
 * <ul>
 *   <li>Extracting the token from the request</li>
 *   <li>Validating the token using a {@link TokenProvider}</li>
 *   <li>Populating the {@link org.springframework.security.core.context.SecurityContext}</li>
 * </ul>
 * </p>
 *
 * <p>
 * The resolution of principals, authorities, or user details is delegated to the
 * {@link JwtAuthenticationConverter}, allowing applications to fully control how
 * authenticated identities are constructed.
 * </p>
 *
 * <p>
 * <strong>Important:</strong> This filter does not authenticate credentials and does not
 * perform authorization decisions. It only establishes authentication based on a valid JWT,
 * following a stateless security model.
 * </p>
 *
 * <p>Thread-safety: This class is stateless and safe for concurrent use.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationConverter authenticationConverter;

    /**
     * Constructs a new JwtAuthenticationFilter.
     *
     * @param tokenProvider the JWT token provider
     * @param authenticationConverter the authentication conversion strategy
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
     * loads user details, validates the token, and sets the resolved Authentication
     * into the SecurityContext if valid.</p>
     *
     * <p>Exceptions during token parsing or validation are logged and do not interrupt the filter chain.</p>
     *
     * @param request     the incoming HTTP request
     * @param response    the HTTP response
     * @param filterChain the filter chain to pass control to the next filter
     * @throws ServletException if an error occurs in the filter processing
     * @throws IOException      if an I/O error occurs during processing
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7); // remove "Bearer "

        try {
            if (!tokenProvider.validateToken(token)) {
                filterChain.doFilter(request, response);
                return;
            }

            String subject = tokenProvider.extractSubject(token);
            if (subject == null) {
                filterChain.doFilter(request, response);
                return;
            }

            Authentication authentication = authenticationConverter.convert(token, subject);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("JWT token validation failed for request: {}", request.getRequestURI());
        } catch (AuthenticationException e) {
            logger.debug("Authentication failed for JWT token: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error while processing JWT token", e);
            throw e;
        }

        filterChain.doFilter(request, response);
    }
}
