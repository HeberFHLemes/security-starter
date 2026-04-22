/*
 * Copyright 2025 Héber F. H. Lemes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.heberfhlemes.securitystarter.config;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;
import io.github.heberfhlemes.securitystarter.properties.JwtProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

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
 *   <li>{@link JwtTokenProvider} — JWT-based token generation and validation.</li>
 *   <li>{@link JwtAuthenticationConverter} — converts a validated token into a
 *       Spring Security {@link org.springframework.security.core.Authentication}.</li>
 *   <li>{@link JwtAuthenticationFilter} — a stateless security filter that extracts
 *       and validates JWTs from incoming requests.</li>
 * </ul>
 *
 * <p>
 * All beans are registered using {@link ConditionalOnMissingBean}, allowing
 * applications to override any component with custom implementations.
 * </p>
 *
 * <p>
 * This configuration is activated automatically when
 * {@link SecurityFilterChain} is present on the classpath and
 * {@link JwtProperties} is enabled.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
@AutoConfiguration
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
    @ConditionalOnMissingBean({JwtTokenProvider.class, TokenProvider.class})
    public JwtTokenProvider jwtTokenProvider(JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Creates a default {@link JwtAuthenticationConverter}
     *
     * <p>
     * This converter is responsible for transforming a validated JWT into a
     * Spring Security {@link org.springframework.security.core.Authentication}
     * instance.
     * </p>
     *
     * @return a JWT authentication converter based on {@link UsernamePasswordAuthenticationToken}
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return subject -> new UsernamePasswordAuthenticationToken(
                subject, null, List.of());
    }

    /**
     * Registers the stateless JWT authentication filter that processes incoming requests
     * and extracts/validates JWT tokens.
     * <p>
     * Applications may override this bean to customize authentication logic or
     * filter ordering.
     *
     * @param tokenProvider the JWT service used for token validation
     * @param converter     an implementation of {@link JwtAuthenticationConverter}
     * @return the default {@link JwtAuthenticationFilter}
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            TokenProvider tokenProvider,
            JwtAuthenticationConverter converter) {
        return new JwtAuthenticationFilter(tokenProvider, converter);
    }
}
