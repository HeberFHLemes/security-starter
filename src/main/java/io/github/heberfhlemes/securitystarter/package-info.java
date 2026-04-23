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
 * A Spring Boot starter providing modular JWT-based authentication.
 *
 * <p>
 * This library offers stateless, modular authentication support based on JWT tokens,
 * designed according to hexagonal architecture principles to keep application code
 * decoupled from infrastructure concerns.
 * </p>
 *
 * <p>Main modules include:</p>
 * <ul>
 *     <li>{@link io.github.heberfhlemes.securitystarter.config} — auto-configuration classes
 *         and helper base class for HTTP security.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.application} — application-layer services
 *         and ports for token management.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt} — low-level JWT token
 *         services.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.filters} — stateless
 *         authentication filters integrated with Spring Security.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.properties} — Configuration properties needed.</li>
 * </ul>
 *
 * <p>
 * <strong>Dependencies:</strong> Applications must include Spring Security
 * ({@code spring-boot-starter-security}) and a runtime implementation of the
 * {@link jakarta.servlet.Servlet} API (e.g., via {@code spring-boot-starter-web}).
 *
 * <p>
 * All components are optional and fully replaceable: applications can provide
 * their own beans, services, or filters as needed.
 * </p>
 *
 * @since 0.1.0
 */
package io.github.heberfhlemes.securitystarter;