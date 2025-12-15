/**
 * Infrastructure components responsible for JWT operations.
 *
 * <p>This package provides low-level utilities for stateless, thread-safe
 * JWT processing, including:</p>
 * <ul>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider} — generates,
 *         parses, and validates JWT tokens.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtProperties} — configuration
 *         properties for JWT, including secret, expiration, and algorithm.</li>
 * </ul>
 *
 * <p>These classes are primarily used internally by higher-level application services
 * such as {@link io.github.heberfhlemes.securitystarter.application.services.TokenAuthenticationService}.</p>
 *
 * @since 1.0.0
 */
package io.github.heberfhlemes.securitystarter.infrastructure.jwt;