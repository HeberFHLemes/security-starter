package io.github.heberfhlemes.securitystarter.config;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.application.services.TokenAuthenticationService;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtProperties;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Auto-configuration for JWT-based stateless authentication.
 *
 * <p>
 * This module registers only the components required for generating, parsing,
 * and validating JWT tokens. It does <strong>not</strong> create authentication-related
 * beans such as {@link org.springframework.security.core.userdetails.UserDetailsService}
 * or {@link org.springframework.security.authentication.AuthenticationProvider};
 * these must be supplied by the application or the core-security module.
 * </p>
 *
 * <p>This configuration provides:</p>
 * <ul>
 *   <li>{@code JwtTokenProvider} — utilities for creating and validating JWT tokens.</li>
 *   <li>{@code JwtAuthenticationFilter} — a stateless authentication filter that
 *       extracts and validates tokens on incoming requests.</li>
 *   <li>Properties mapping for secret keys, expiration time, and algorithm.</li>
 * </ul>
 *
 * <p>The application must supply a {@link UserDetailsService}, which is used by
 * the filter to load user details when a valid token is detected. All other
 * authentication-related concerns (password policies, authentication providers,
 * login endpoints, etc.) are handled outside of this module.</p>
 *
 * <p>
 * This keeps JWT support fully modular and allows the consumer to plug it
 * into any architecture or security configuration they prefer.
 * </p>
 *
 * <p>
 * This configuration is applied <strong>after</strong> the core security
 * setup provided by {@link CoreSecurityAutoConfiguration}. It is activated
 * automatically when {@link org.springframework.security.web.SecurityFilterChain}
 * is present on the classpath and {@link JwtProperties} is enabled via
 * configuration properties. It registers the JWT filter, token service, and
 * supporting beans.
 * </p>
 *
 * <p>
 * Although this configuration exposes generic token-related services, all default
 * implementations provided by this module are JWT-based.
 * </p>
 *
 * @see CoreSecurityAutoConfiguration
 * @author Héber F. H. Lemes
 * @since 1.0.0
 */
@AutoConfiguration(after = CoreSecurityAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    /**
     * Creates a default JWT-based {@link TokenProvider} using the configured
     * {@link JwtProperties}.
     *
     * <p>
     * Applications may override this bean to provide a different {@link TokenProvider}
     * implementation.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean(TokenProvider.class)
    public TokenProvider tokenProvider(JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Registers the JWT authentication filter that processes incoming requests and
     * extracts/validates JWT tokens.
     * <p>
     * Applications may override this bean to customize authentication logic or
     * filter ordering.
     *
     * @param tokenProvider the JWT service used for token validation
     * @param userDetailsService the user details service used for authentication lookup
     * @return the default JWT-based {@link OncePerRequestFilter}
     */
    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationFilter.class)
    public OncePerRequestFilter jwtAuthenticationFilter(
            TokenProvider tokenProvider,
            UserDetailsService userDetailsService) {
        return new JwtAuthenticationFilter(tokenProvider, userDetailsService);
    }

    /**
     * Provides a simple token-based authentication service wrapper.
     *
     * <p>
     * In this starter, the default implementation is backed by a JWT-based
     * {@link TokenProvider}.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean(TokenAuthenticationService.class)
    public TokenAuthenticationService tokenAuthenticationService(TokenProvider tokenProvider) {
        return new TokenAuthenticationService(tokenProvider);
    }

}
