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
package io.github.heberfhlemes.securitystarter.core;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.function.Function;

/**
 * Factory methods for common {@link TokenAuthenticationConverter} implementations.
 *
 * <p>All converters produced by this class follow the same contract:
 * <ul>
 *   <li>Return {@code null} if the token is invalid or has no subject.</li>
 *   <li>Use {@code token.subject()} as the principal.</li>
 *   <li>Set credentials to {@code null} (stateless authentication).</li>
 * </ul>
 */
public final class TokenAuthenticationConverters {

    private TokenAuthenticationConverters() {
    }

    /**
     * Creates a {@link TokenAuthenticationConverter} that produces an
     * {@link UsernamePasswordAuthenticationToken} containing only the subject
     * as the principal and no authorities.
     *
     * <p>No authorities are assigned (empty collection).
     *
     * @return a converter that extracts only the subject as principal
     */
    public static TokenAuthenticationConverter subjectOnly() {
        return token -> {
            if (!token.valid() || token.subject() == null) {
                return null;
            }

            return new UsernamePasswordAuthenticationToken(
                    token.subject(), null, List.of());
        };
    }

    /**
     * Creates a {@link TokenAuthenticationConverter} that converts a valid token
     * into a {@link UsernamePasswordAuthenticationToken}, extracting authorities
     * using the provided function.
     *
     * @param authoritiesExtractor function responsible for extracting authorities
     *                             from the token; must not return {@code null}
     * @return a configured {@link TokenAuthenticationConverter}
     */
    public static TokenAuthenticationConverter withAuthorities(
            Function<TokenValidationResult, Collection<? extends GrantedAuthority>> authoritiesExtractor
    ) {
        return token -> {
            if (!token.valid() || token.subject() == null) {
                return null;
            }

            return new UsernamePasswordAuthenticationToken(
                    token.subject(), null, authoritiesExtractor.apply(token));
        };
    }

    /**
     * Creates a {@link TokenAuthenticationConverter} that extracts roles from a
     * token claim and maps them to {@link GrantedAuthority}.
     *
     * <p>The claim is expected to be a list of strings.
     *
     * <p>Each role is mapped directly to a {@link SimpleGrantedAuthority}
     * without any prefix transformation.
     *
     * @param claimName the name of the claim containing the roles
     * @return a converter that maps claim values to authorities
     */
    public static TokenAuthenticationConverter rolesFromClaim(String claimName) {
        return token -> {
            if (!token.valid() || token.subject() == null) {
                return null;
            }

            List<String> roles = token.claims().getList(claimName);

            Collection<? extends GrantedAuthority> authorities =
                    roles == null
                            ? List.of()
                            : roles.stream()
                              .map(SimpleGrantedAuthority::new)
                              .toList();

            return new UsernamePasswordAuthenticationToken(
                    token.subject(), null, authorities);
        };
    }
}
