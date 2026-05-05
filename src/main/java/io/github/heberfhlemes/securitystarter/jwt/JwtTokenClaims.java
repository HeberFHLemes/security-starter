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
package io.github.heberfhlemes.securitystarter.jwt;

import io.github.heberfhlemes.securitystarter.core.TokenClaims;
import io.jsonwebtoken.Claims;

/**
 * A {@link TokenClaims} implementation that delegates
 * its operations to {@link Claims}, from {@code jjwt} library.
 *
 * @author Héber F. H. Lemes
 * @since 0.4.0
 */
public class JwtTokenClaims implements TokenClaims {

    private final Claims delegate;

    /**
     * Creates a new {@code JwtTokenClaims} wrapping the given {@link Claims}.
     *
     * @param claims the {@link Claims} to delegate to
     */
    public JwtTokenClaims(Claims claims) {
        this.delegate = claims;
    }

    @Override
    public Object get(String name) {
        return this.delegate.get(name);
    }
}