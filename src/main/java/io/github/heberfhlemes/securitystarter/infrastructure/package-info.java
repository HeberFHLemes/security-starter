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
 * Infrastructure layer for the {@code security-starter}.
 *
 * <p>
 * This package contains technical components that implement low-level authentication
 * behavior, such as JWT token processing and request filtering. Components here
 * are used by higher-level application services and should remain decoupled from
 * application logic.
 * </p>
 *
 * <p>Subpackages include:</p>
 * <ul>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt} — JWT token
 *         providers</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.filters} — stateless
 *         authentication filters integrated with Spring Security.</li>
 * </ul>
 *
 * <p>
 * All components are intended to be used internally by the application layer services.
 * </p>
 *
 * @since 0.1.0
 */
package io.github.heberfhlemes.securitystarter.infrastructure;