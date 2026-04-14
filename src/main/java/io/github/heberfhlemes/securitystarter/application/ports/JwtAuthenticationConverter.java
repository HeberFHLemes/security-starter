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
package io.github.heberfhlemes.securitystarter.application.ports;

import org.springframework.security.core.Authentication;

/**
 * Strategy interface responsible for converting a validated token and its
 * subject into a Spring Security {@link Authentication} instance.
 *
 * <p>This abstraction allows applications to customize how principals,
 * authorities, or additional details are resolved from a token.</p>
 *
 * @author Héber F. H. Lemes
 * @since 0.2.0
 */
public interface JwtAuthenticationConverter {
    /**
     * Converts a validated JWT token and its subject into a Spring Security
     * {@link Authentication} instance.
     *
     * <p>The returned authentication is expected to be fully authenticated
     * and suitable for storage in the {@link org.springframework.security.core.context.SecurityContext}.</p>
     *
     * @param token   the raw JWT token
     * @param subject the subject extracted from the token (usually the username)
     * @return an authenticated {@link Authentication} instance, or {@code null}
     * if the token cannot be converted
     * @since 0.2.0
     */
    Authentication convert(String token, String subject);
}
