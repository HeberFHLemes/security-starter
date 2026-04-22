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

import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;
import org.jspecify.annotations.NonNull;
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
@FunctionalInterface
public interface JwtAuthenticationConverter {
    /**
     * Converts a defined subject into a Spring Security {@link Authentication} instance.
     *
     * @param tokenValidationResult the result obtained from validating a token.
     * @return an authenticated {@link Authentication} instance, or {@code null}
     * if the token cannot be converted
     * @since 0.3.2
     */
    Authentication convert(@NonNull TokenValidationResult tokenValidationResult);
}
