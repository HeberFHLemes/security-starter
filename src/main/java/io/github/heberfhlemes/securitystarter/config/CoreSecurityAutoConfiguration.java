package io.github.heberfhlemes.securitystarter.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Auto-configuration for the core security components provided by the
 * {@code security-starter}. This class registers the minimum required beans
 * for password handling and authentication unless the application defines its
 * own overrides.
 *
 * <p>This configuration provides:</p>
 * <ul>
 *   <li>{@link org.springframework.security.crypto.password.PasswordEncoder}
 *       — a default BCrypt implementation, overridable by defining another bean.</li>
 *   <li>{@link org.springframework.security.authentication.AuthenticationProvider}
 *       — a {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
 *       wired with the application's {@link org.springframework.security.core.userdetails.UserDetailsService}.</li>
 *   <li>{@link org.springframework.security.authentication.AuthenticationManager}
 *       — exposed from {@link org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration}.</li>
 * </ul>
 *
 * <p><strong>Note:</strong> This module does <em>not</em> provide a
 * {@link org.springframework.security.core.userdetails.UserDetailsService}.
 * Applications must supply one, as it defines how users are loaded. Without it,
 * Spring Security will fail to create the authentication provider.</p>
 *
 * <p>Users may override any provided bean by defining one with the same type.
 * This keeps the starter modular, framework-agnostic, and aligned with
 * hexagonal architecture principles.</p>
 *
 * <p>Loaded automatically via Spring Boot’s auto-configuration mechanism.</p>
 *
 * @author Héber F. H. Lemes
 * @since 1.0.0
 */
@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class CoreSecurityAutoConfiguration {

    /**
     * Registers a default {@link PasswordEncoder} using BCrypt.
     * <p>
     * Applications may override this bean if a different password hashing strategy
     * is required.
     *
     * @return a BCrypt-based {@link PasswordEncoder}
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Creates a default {@link AuthenticationProvider} using the provided
     * {@link UserDetailsService} and {@link PasswordEncoder}.
     * <p>
     * Applications may override this bean to customize authentication mechanisms
     * or integrate alternative providers.
     *
     * @param userDetailsService the user lookup service
     * @param passwordEncoder    the password encoder used for credential validation
     * @return a configured {@link AuthenticationProvider}
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                         PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    /**
     * Exposes the {@link AuthenticationManager} obtained from
     * {@link AuthenticationConfiguration}. This allows applications to inject and
     * use the authentication manager provided by Spring Security.
     * <p>
     * Applications may override this bean if they need full control over the
     * authentication manager creation.
     *
     * @param config the security configuration used to resolve the manager
     * @return the application's {@link AuthenticationManager}
     * @throws Exception if the manager could not be created
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}
