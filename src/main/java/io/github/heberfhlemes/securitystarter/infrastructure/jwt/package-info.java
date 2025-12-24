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