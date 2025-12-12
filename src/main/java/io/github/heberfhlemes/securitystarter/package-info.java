/**
 * A Spring Boot starter providing modular JWT-based authentication.
 *
 * <p>
 * This library provides modular, stateless authentication support,
 * primarily based on JWT tokens. It is designed following hexagonal architecture
 * principles, keeping application code decoupled from infrastructure concerns.
 * </p>
 *
 * <p>Main modules include:</p>
 * <ul>
 *     <li>{@link io.github.heberfhlemes.securitystarter.config} — auto-configuration classes
 *         and helper base class for HTTP security.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.application} — application-layer services
 *         for token management.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.jwt} — low-level JWT token
 *         services and configuration properties.</li>
 *     <li>{@link io.github.heberfhlemes.securitystarter.infrastructure.filters} — stateless
 *         authentication filters integrated with Spring Security.</li>
 * </ul>
 *
 * <p>
 * <strong>Required dependencies:</strong> Applications must include Spring Security
 * ({@code spring-boot-starter-security}),
 * and a runtime implementation of {@link jakarta.servlet.Servlet} API
 * (such as via {@code spring-boot-starter-web}).
 * Required Spring Security classes include
 * {@link org.springframework.security.web.SecurityFilterChain} and
 * {@link org.springframework.security.core.userdetails.UserDetailsService}.
 * </p>
 *
 * <p>
 * The library is intended to be optional and fully replaceable at any layer:
 * applications can provide their own beans, services, or filters as needed.
 * </p>
 *
 * @since 1.0.0
 */
package io.github.heberfhlemes.securitystarter;