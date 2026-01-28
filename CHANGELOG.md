# Changelog

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