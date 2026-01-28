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
 * Required Spring Security classes include
 * {@link org.springframework.security.web.SecurityFilterChain} and
 * {@link org.springframework.security.core.userdetails.UserDetailsService}.
 * </p>
 *
 * <p>
 * All components are optional and fully replaceable: applications can provide
 * their own beans, services, or filters as needed.
 * </p>
 *
 * @since 0.1.0
 */
package io.github.heberfhlemes.securitystarter;