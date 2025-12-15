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
 *         providers and configuration properties.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.filters} — stateless
 *         authentication filters integrated with Spring Security.</li>
 * </ul>
 *
 * <p>
 * All components are intended to be used internally by the application layer services.
 * </p>
 *
 * @since 1.0.0
 */
package io.github.heberfhlemes.securitystarter.infrastructure;