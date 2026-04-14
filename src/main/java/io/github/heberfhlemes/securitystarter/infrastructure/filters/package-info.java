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
 * Contains servlet filters used by the {@code security-starter} library
 * to integrate with the Spring Security filter chain.
 *
 * <p>
 * This package includes stateless authentication filters, such as
 * {@link io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter},
 * which are responsible for extracting and validating authentication tokens
 * from incoming HTTP requests.
 * </p>
 *
 * @since 0.1.0
 */
@NullMarked
package io.github.heberfhlemes.securitystarter.infrastructure.filters;

import org.jspecify.annotations.NullMarked;