package io.github.heberfhlemes.securitystarter.config;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.application.services.TokenAuthenticationService;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.UserDetailsJwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.properties.JwtProperties;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Auto-configuration for JWT-based stateless authentication.
 *
 * <p>
 * This module registers only the infrastructure components required for
 * generating, parsing, converting, and validating JWT tokens. It does
 * <strong>not</strong> create authentication-related domain beans such as
 * {@link UserDetailsService} or {@link AuthenticationProvider}; these must be
 * supplied by the application or a higher-level security module.
 * </p>
 *
 * <p>This configuration provides the following default beans:</p>
 * <ul>
 *   <li>{@link TokenProvider} — JWT-based token generation and validation.</li>
 *   <li>{@link JwtAuthenticationConverter} — converts a validated token into a
 *       Spring Security {@link org.springframework.security.core.Authentication}.</li>
 *   <li>{@link JwtAuthenticationFilter} — a stateless security filter that extracts
 *       and validates JWTs from incoming requests.</li>
 *   <li>{@link TokenAuthenticationService} — a simple facade for token operations,
 *       intended for use in controllers or application services.</li>
 * </ul>
 *
 * <p>
 * All beans are registered using {@link ConditionalOnMissingBean}, allowing
 * applications to override any component with custom implementations.
 * </p>
 *
 * <p>
 * The application must supply a {@link UserDetailsService}, which is used by the
 * default {@link JwtAuthenticationConverter} to load user details when a valid
 * token is detected.
 * </p>
 *
 * <p>
 * This configuration is applied <strong>after</strong>
 * {@link CoreSecurityAutoConfiguration} and is activated automatically when
 * {@link SecurityFilterChain} is present on the classpath and
 * {@link JwtProperties} is enabled.
 * </p>
 *
 * @see CoreSecurityAutoConfiguration
 * @author Héber F. H. Lemes
 * @since 0.1.0
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
     * Applications may override this bean to provide a different
     * {@link TokenProvider} implementation.
     * </p>
     *
     * @param properties JWT configuration properties
     * @return a JWT-based {@link TokenProvider}
     */
    @Bean
    @ConditionalOnMissingBean(TokenProvider.class)
    public TokenProvider tokenProvider(JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Creates a default {@link JwtAuthenticationConverter} backed by a
     * {@link UserDetailsService}.
     *
     * <p>
     * This converter is responsible for transforming a validated JWT into a
     * Spring Security {@link org.springframework.security.core.Authentication}
     * instance.
     * </p>
     *
     * <p>
     * This bean is only created if a {@link UserDetailsService} is present in the
     * application context.
     * </p>
     *
     * @param userDetailsService the service used to load user details from the token subject
     * @return a JWT authentication converter based on {@link UserDetailsService}
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserDetailsService.class)
    public JwtAuthenticationConverter jwtAuthenticationConverter(
            UserDetailsService userDetailsService) {
        return new UserDetailsJwtAuthenticationConverter(userDetailsService);
    }

    /**
     * Registers the stateless JWT authentication filter that processes incoming requests
     * and extracts/validates JWT tokens.
     * <p>
     * Applications may override this bean to customize authentication logic or
     * filter ordering.
     *
     * @param tokenProvider the JWT service used for token validation
     * @param converter an implementation of {@link JwtAuthenticationConverter}
     * @return the default {@link JwtAuthenticationFilter}
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            TokenProvider tokenProvider,
            JwtAuthenticationConverter converter) {
        return new JwtAuthenticationFilter(tokenProvider, converter);
    }

    /**
     * Provides a simple token-based authentication service facade.
     *
     * <p>
     * This service is intended for use in controllers or application services
     * to generate and validate tokens without directly interacting with the
     * underlying {@link TokenProvider}.
     * </p>
     *
     * <p>
     * In this starter, the default implementation is backed by a JWT-based
     * {@link TokenProvider}.
     * </p>
     *
     * @param tokenProvider the token provider implementation
     * @return a token authentication service
     */
    @Bean
    @ConditionalOnMissingBean(TokenAuthenticationService.class)
    public TokenAuthenticationService tokenAuthenticationService(TokenProvider tokenProvider) {
        return new TokenAuthenticationService(tokenProvider);
    }
}
