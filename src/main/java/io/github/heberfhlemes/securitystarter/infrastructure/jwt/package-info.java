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
/**
 * Infrastructure components responsible for JWT-based security support.
 *
 * <p>
 * This package contains stateless, thread-safe implementations related to
 * JSON Web Token (JWT) handling, including token creation, parsing, and validation.
 * </p>
 *
 * <p>Provided components include:</p>
 * <ul>
 *     <li>
 *         {@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider} —
 *         default infrastructure implementation of the
 *         {@link io.github.heberfhlemes.securitystarter.application.ports.TokenProvider}
 *         contract.
 *     </li>
 * </ul>
 *
 * <p>
 * JWT behavior is configured via
 * {@link io.github.heberfhlemes.securitystarter.properties.JwtProperties},
 * which are bound to the {@code securitystarter.jwt} configuration namespace.
 * </p>
 *
 * @since 0.1.0
 */
package io.github.heberfhlemes.securitystarter.infrastructure.jwt;