package io.github.heberfhlemes.securitystarter.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Base class for applications to customize their HTTP security configuration
 * when using the Security Starter.
 *
 * <p>This class provides helper methods for applying common security settings,
 * such as disabling CSRF and configuring stateless session management.</p>
 *
 * <p>Applications may extend this class to simplify the creation of their
 * {@link org.springframework.security.web.SecurityFilterChain} beans.
 * The {@link #configureAuthorization} method must be implemented to specify
 * route authorization rules.</p>
 *
 * <p>This class is not a Spring bean and is not instantiated by the starter.
 * It serves solely as an extension point for user-defined security
 * configurations. Applications are free to ignore this class and configure
 * Spring Security manually.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
public abstract class SecurityConfigurationSupport {

    /**
     * Configures common security settings for HTTP requests, including disabling CSRF protection
     * and setting the session management to stateless. Optionally, adds a stateless authentication
     * filter before the {@link UsernamePasswordAuthenticationFilter}.
     *
     * @param http the {@link HttpSecurity} object to configure
     * @param authenticationFilter an optional {@link OncePerRequestFilter} used for stateless
     *                             authentication. If provided, it will be added before the
     *                             {@link UsernamePasswordAuthenticationFilter}.
     */
    protected void configureCommonSecurity(HttpSecurity http, OncePerRequestFilter authenticationFilter) {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (authenticationFilter != null) {
            http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
        }
    }

    /**
     * Configures common security settings for HTTP requests, including disabling CSRF protection
     * and setting the session management to stateless.
     *
     * @param http the {@link HttpSecurity} object to configure
     */
    protected void configureCommonSecurity(HttpSecurity http) {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }

    /**
     * Abstract method to be implemented by subclasses for defining custom authorization rules.
     * This method is used to specify which routes should be accessible to which roles or users.
     *
     * @param auth the {@link AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry}
     *             object that allows you to define authorization rules for specific HTTP request patterns.
     *
     * @see HttpSecurity#authorizeHttpRequests(Customizer)
     */
    protected abstract void configureAuthorization(
            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth
    );

}
