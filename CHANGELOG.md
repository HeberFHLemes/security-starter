# Changelog

<!-- TOC -->
* [Changelog](#changelog)
  * [[0.3.1] - 2026-04-14](#031---2026-04-14)
    * [Changed](#changed)
    * [Added](#added)
    * [Deprecated](#deprecated)
  * [[0.3.0] - 2026-02-11](#030---2026-02-11)
    * [Breaking Changes](#breaking-changes)
    * [Changed](#changed-1)
    * [Added](#added-1)
  * [[0.2.0] - 2026-01-28](#020---2026-01-28)
    * [Breaking Changes](#breaking-changes-1)
    * [Changed](#changed-2)
    * [Added](#added-2)
    * [Fixed](#fixed)
    * [Internal](#internal)
  * [[0.1.1] - 2025-12-24](#011---2025-12-24)
    * [Added](#added-3)
    * [Fixed](#fixed-1)
    * [Internal](#internal-1)
  * [[0.1.0] - 2025-12-21](#010---2025-12-21)
    * [Added](#added-4)
<!-- TOC -->

---

## [0.3.1] - 2026-04-14

### Changed

* Replaced default `PasswordEncoder` from `BCryptPasswordEncoder` to `DelegatingPasswordEncoder`
* Extended `JwtTokenProvider` with support for custom claims during token generation
* Added optional issuer claim support in `JwtProperties`
* Bumped Spring Boot version to 4.0.5 (for BOM)

### Added

* Overloaded `generateToken` method in `JwtTokenProvider` allowing custom JWT claims via `JwtBuilder`

### Deprecated

* Marked `TokenAuthenticationService` as deprecated

## [0.3.0] - 2026-02-11

### Breaking Changes

* Replaced primitive return types in `TokenProvider` with structured records:

    * `generateToken` now returns `GeneratedToken`
    * `validate` now returns `TokenValidationResult`
* Removed legacy validation methods in favor of a single structured validation flow

### Changed

* Refactored token API to provide richer and more cohesive validation results
* Simplified `JwtTokenProvider` implementation
* Introduced `Clock` injection into `JwtTokenProvider` for deterministic expiration handling
* Improved Javadocs across token-related components
* Updated tests and dependent classes to align with the new token API

### Added

* `GeneratedToken` record to encapsulate token metadata (token, issuedAt, expiresAt)
* `TokenValidationResult` record to encapsulate validation outcome and extracted claims

---

## [0.2.0] - 2026-01-28

### Breaking Changes

- Standardized configuration properties prefix for `JwtProperties` to `securitystarter.jwt`
- Simplified token validation API by removing subject-based validation

### Changed

- Improved separation between application ports and infrastructure implementations

### Added

- JWT authentication converter abstraction (`JwtAuthenticationConverter`)
- Default `UserDetails`-based `JwtAuthenticationConverter` implementation
- Automatic integration of the converter into the JWT authentication filter

### Fixed

- Inconsistencies in README examples and wording, Javadocs and package-level documentation.

### Internal

- Refactored internal contracts to better align with hexagonal architecture
- Added new tests and updated the existing ones to reflect the new validation semantics

---

## [0.1.1] - 2025-12-24

### Added

- README badges (Maven Central and License)

### Fixed

- Changelog release dates
- Javadocs `@since` versions
- Minor documentation inconsistencies

### Internal

- Removed unused `.gitattributes` file
- Cleaned up CI/deployment artifacts not used for release publishing

## [0.1.0] - 2025-12-21

### Added

- Initial release
- JWT-based stateless authentication starter for Spring Boot 4 and Spring Security
- Auto-configuration for Spring Security, JWT and authentication filters