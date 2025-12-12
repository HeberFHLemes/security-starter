/**
 * Infrastructure components responsible for JWT operations.
 *
 * <p>This includes:</p>
 * <ul>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtService} — responsible for generating and validating tokens.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtProperties} — configuration properties such as secret, expiration,
 *         and algorithm.</li>
 * </ul>
 *
 * <p>These classes encapsulate low-level JWT behavior and are used internally
 * by higher-level services.</p>
 *
 * @since 1.0.0
 */
package io.github.heberfhlemes.securitystarter.infrastructure.jwt;