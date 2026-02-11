/**
 * Application layer components responsible for JWT generation,
 * validation, and token-related data transfer structures.
 *
 * <p>This package contains abstractions and implementations
 * that encapsulate token handling logic without exposing
 * infrastructure-specific details to upper layers.</p>
 *
 * <p>The goal is to keep token management cohesive,
 * testable, and independent from web or persistence concerns.</p>
 *
 * @apiNote Tokens are stateless and must not contain sensitive domain data.
 * @since 0.3.0
 */
package io.github.heberfhlemes.securitystarter.application.token;