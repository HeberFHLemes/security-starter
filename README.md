# Security Starter

JWT-based stateless authentication for Spring Boot

[![CI/CD Pipeline](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.heberfhlemes/security-starter)](https://search.maven.org/artifact/io.github.heberfhlemes/security-starter)
![License](https://img.shields.io/github/license/HeberFHLemes/security-starter)

A Spring Boot starter to simplify **Spring Security configuration** for JWT-based stateless authentication.
It **abstracts JWT authentication logic**, while keeping your application modular and decoupled
from infrastructure.

---

## Requirements

- Java 17+
- Spring Boot 4.x
- Spring Security
- A Jakarta Servlet API implementation (typically provided by Spring Web)

---

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.heberfhlemes</groupId>
    <artifactId>security-starter</artifactId>
    <version>0.3.1</version>
</dependency>
```

---

## Configuration

### JWT Properties

In your `application.properties` or `application.yml`:

```yaml
securitystarter:
  jwt:
    secret: ${JWT_SECRET}
    expiration: 720000 # 12 minutes (milliseconds)
    issuer: # optional JWT "iss" (issuer) claim
```

### SecurityConfigurationSupport

This is entirely optional. You can extend SecurityConfigurationSupport to define route authorization policies
while reusing common security configuration logic.

```java
@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends SecurityConfigurationSupport {

    @Override
    protected void configureAuthorization(
            AuthorizeHttpRequestsConfigurer<HttpSecurity>
                    .AuthorizationManagerRequestMatcherRegistry auth) {
        auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter
    ) throws Exception {
        configureCommonSecurity(http, jwtFilter); // from SecurityConfigurationSupport
        configureAuthorization(http.authorizeHttpRequests());
        return http.build();
    }
}
```

### Creating a custom UserDetailsService implementation

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new UserPrincipal(user); // implements UserDetails
    }
}
```

### Using TokenProvider

Generate and validate tokens:

```java
@Service
public class AuthService {

    private final TokenProvider tokenProvider;

    public AuthResponse login(LoginRequest request) {
        User user = authenticateUser(request);
        GeneratedToken token = tokenProvider.generateToken(user.getEmail());
        return AuthResponse.from(token);
    }

    public void validateToken(String tokenString) {
        TokenValidationResult result = tokenProvider.validate(tokenString);
        if (!result.valid()) {
            throw new InvalidTokenException("Token validation failed");
        }
    }
}
```

---

## Overriding Beans

All core Spring beans are declared with `@ConditionalOnMissingBean`, allowing full customization:

- `PasswordEncoder`
- `TokenProvider`
- `JwtAuthenticationConverter`
- `JwtAuthenticationFilter`

This starter provides authentication infrastructure only.
It does not include controllers, route definitions, or user persistence.

---

## License

This project is licensed under [Apache License, Version 2.0.](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.
