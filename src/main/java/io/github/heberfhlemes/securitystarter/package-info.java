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
 * A Spring Boot starter providing JWT-based stateless authentication.
 *
 * <p>
 * This library reduces boilerplate for securing Spring Boot applications
 * with JWT tokens, offering sensible defaults while remaining fully customizable.
 * </p>
 *
 * <h2>Getting started</h2>
 * <ol>
 *   <li>Enable JWT support: {@code securitystarter.jwt.enabled=true}</li>
 *   <li>Configure the secret and expiration under {@code securitystarter.jwt.*}</li>
 *   <li>Apply the minimal security configuration using
 *       {@link io.github.heberfhlemes.securitystarter.web.JwtSecurityConfigurer}</li>
 * </ol>
 *
 * <h2>Key abstractions</h2>
 * <ul>
 *   <li>{@link io.github.heberfhlemes.securitystarter.core.TokenProvider} —
 *       generates and validates tokens</li>
 *   <li>{@link io.github.heberfhlemes.securitystarter.core.TokenAuthenticationConverter} —
 *       converts a validated token into a Spring Security {@code Authentication}</li>
 * </ul>
 *
 * <h2>Requirements</h2>
 * <p>
 * Requires {@code spring-boot-starter-security} and a Jakarta Servlet API
 * implementation (e.g. {@code spring-boot-starter-web}).
 * </p>
 *
 * <p>All beans are conditional and fully replaceable.</p>
 *
 * @since 0.1.0
 */
package io.github.heberfhlemes.securitystarter;