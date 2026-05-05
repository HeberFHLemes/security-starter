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
package io.github.heberfhlemes.securitystarter.autoconfigure;

import io.github.heberfhlemes.securitystarter.core.TokenAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.core.TokenAuthenticationConverters;
import io.github.heberfhlemes.securitystarter.core.TokenProvider;
import io.github.heberfhlemes.securitystarter.jwt.JwtTokenProvider;
import io.github.heberfhlemes.securitystarter.properties.JwtProperties;
import io.github.heberfhlemes.securitystarter.web.JwtAuthenticationFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Auto-configuration for JWT-based stateless authentication.
 *
 * <p>
 * This module registers components required for generating, parsing,
 * converting, and validating JWT tokens.
 * </p>
 *
 * <p>
 * All beans are registered using {@link ConditionalOnMissingBean}, allowing
 * applications to override any component with custom implementations.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "securitystarter.jwt", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    /**
     * Registers a default {@link JwtTokenProvider} using the configured
     * {@link JwtProperties}.
     *
     * <p>Exposes the concrete type to allow injection of
     * {@link JwtTokenProvider} directly when custom token generation
     * is needed.</p>
     *
     * <p>Skipped if any {@link TokenProvider} bean is already present.</p>
     *
     * @param properties JWT configuration properties
     * @return a {@link JwtTokenProvider} instance
     */
    @Bean
    @ConditionalOnMissingBean({JwtTokenProvider.class, TokenProvider.class})
    public JwtTokenProvider jwtTokenProvider(JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Registers the stateless JWT authentication filter that processes incoming requests
     * and extracts/validates JWT tokens.
     * <p>
     *
     * @param tokenProvider the JWT service used for token validation
     * @param converter     an implementation of {@link TokenAuthenticationConverter}
     * @return the default {@link JwtAuthenticationFilter}
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(OncePerRequestFilter.class)
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            TokenProvider tokenProvider,
            TokenAuthenticationConverter converter) {
        return new JwtAuthenticationFilter(tokenProvider, converter);
    }

    /**
     * Registers a TokenAuthenticationConverter bean, as a default, using only
     * the subject provided. It is recommended to define another
     * {@link TokenAuthenticationConverter} bean, like with
     * {@code TokenAuthenticationConverters.rolesFromClaim("roles")}.
     *
     * @return the default TokenAuthenticationConverter, using only a subject.
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenAuthenticationConverter tokenAuthenticationConverter() {
        return TokenAuthenticationConverters.subjectOnly();
    }
}
