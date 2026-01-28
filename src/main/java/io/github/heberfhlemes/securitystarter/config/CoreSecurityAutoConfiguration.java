package io.github.heberfhlemes.securitystarter.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
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
 * </ul>
 *
 * <p>
 *     <strong>Note:</strong> This module does <em>not</em> provide a
 * {@link org.springframework.security.core.userdetails.UserDetailsService}.
 * Applications must supply one, as it defines how users are loaded. Without it,
 * Spring Security will fail to create the authentication provider.
 * </p>
 *
 * <p>
 *     Users may override any provided bean by defining one with the same type.
 * </p>
 *
 * <p>
 *     Loaded automatically via Spring Boot’s auto-configuration mechanism.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
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

}
