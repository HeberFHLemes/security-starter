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
package io.github.heberfhlemes.securitystarter.application.token;

import java.time.Instant;

/**
 * Result of a JWT validation attempt.
 *
 * <p>Contains the validation status and, if valid,
 * the extracted subject and expiration timestamp.</p>
 *
 * @param valid     whether the token is valid
 * @param subject   the token subject (typically the user identifier), or {@code null} if invalid
 * @param expiresAt the token expiration instant, or {@code null} if invalid
 * @author Héber F. H. Lemes
 * @since 0.3.0
 */
public record TokenValidationResult(
        boolean valid,
        String subject,
        Instant expiresAt
) {
}
