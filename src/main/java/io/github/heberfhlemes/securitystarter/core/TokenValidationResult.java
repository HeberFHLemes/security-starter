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

import java.time.Instant;

/**
 * Result of a JWT validation attempt.
 *
 * <p>Contains the validation status and, if valid,
 * the extracted subject and expiration timestamp.</p>
 *
 * @param valid     whether the token is valid
 * @param subject   the token subject, or {@code null} if invalid
 * @param expiresAt the token expiration instant, or {@code null} if invalid
 * @param claims    the {@link TokenClaims} holding the extracted claims
 * @author Héber F. H. Lemes
 * @since 0.3.0
 */
public record TokenValidationResult(
        boolean valid,
        String subject,
        Instant expiresAt,
        TokenClaims claims
) {
    /**
     * Creates a {@link TokenValidationResult} marked as invalid, and with
     * all the other attributes as null or empty.
     *
     * @return an invalid {@link TokenValidationResult} object
     */
    public static TokenValidationResult buildInvalid() {
        return new TokenValidationResult(false, null, null, TokenClaims.empty());
    }

    /**
     * Returns whether this result represents an authenticated token —
     * that is, the token is valid and has a non-null subject.
     *
     * @return {@code true} if the token is valid and the subject is present
     */
    public boolean isAuthenticated() {
        return valid && subject != null;
    }
}
