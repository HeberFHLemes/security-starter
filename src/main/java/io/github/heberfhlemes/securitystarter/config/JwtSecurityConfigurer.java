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

import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Base JWT security configuration, applying filter and stateless policy.
 *
 * @author Héber F. H. Lemes
 * @since 0.3.2
 */
public final class JwtSecurityConfigurer {

    private JwtSecurityConfigurer() {
    }

    /**
     * Applies STATELESS session policy, adds a {@link JwtAuthenticationFilter}
     * before the default authentication filter, and disable CSRF.
     *
     * @param http a {@link HttpSecurity}
     * @param filter a {@link JwtAuthenticationFilter}
     */
    public static void applyTo(HttpSecurity http, JwtAuthenticationFilter filter) {
        try {
            http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(session ->
                            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply JWT security configuration", e);
        }
    }
}
