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
package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Default JWT authentication converter that resolves user details using a
 * {@link UserDetailsService}.
 *
 * <p>This implementation produces an authenticated
 * {@link UsernamePasswordAuthenticationToken}.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.2.0
 */
public class UserDetailsJwtAuthenticationConverter implements JwtAuthenticationConverter {

    private final UserDetailsService userDetailsService;

    /**
     * Constructs a new converter using the given {@link UserDetailsService}.
     *
     * @param userDetailsService service used to load user details from the JWT subject
     */
    public UserDetailsJwtAuthenticationConverter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication convert(String token, String subject) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }
}
