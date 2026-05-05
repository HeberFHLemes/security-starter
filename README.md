# security-starter

JWT-based stateless authentication for Spring Boot

[![CI/CD Pipeline](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.heberfhlemes/security-starter)](https://search.maven.org/artifact/io.github.heberfhlemes/security-starter)
![License](https://img.shields.io/github/license/HeberFHLemes/security-starter)

A Spring Boot starter that simplifies Spring Security configuration
for JWT-based stateless authentication. It reduces boilerplate and
provides defaults while remaining fully customizable.

---

## Requirements

- Java 17+
- Spring Boot 4.x
- Spring Security
- A Jakarta Servlet API implementation (e.g. `spring-boot-starter-web`)

---

## Installation

```xml
<dependency>
    <groupId>io.github.heberfhlemes</groupId>
    <artifactId>security-starter</artifactId>
    <version>0.3.2</version>
</dependency>
```

---

## Configuration

### JWT Properties

```yaml
securitystarter:
  jwt:
    enabled: true
    secret: ${JWT_SECRET}        # required, minimum 32 bytes
    expiration: PT12M            # ISO-8601 duration, defaults to 12 minutes
    issuer:                      # optional "iss" claim
```

### Security configuration

Use `JwtSecurityConfigurer.applyTo()` to apply the minimal stateless
security setup: disables CSRF, sets session policy to STATELESS,
and registers the JWT filter.

```java
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    // ...

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtSecurityConfigurer.applyTo(http, jwtFilter);

        return http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
        ).build();
    }
}
```

> If your application uses session-based authentication alongside JWT,
> configure `HttpSecurity` manually instead of using `JwtSecurityConfigurer`.

### Disabling UserDetailsServiceAutoConfiguration

Since this library uses stateless JWT authentication, Spring Security's
default `UserDetailsService` is not needed. Excluding it prevents
the auto-generated password from being created at startup.

```java
@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

---

## Generating tokens

```java
@Service
public class AuthService {

    private final JwtTokenProvider tokenProvider;

    // ...

    public AuthResponse login(LoginRequest request) {
        // authenticate user...
        GeneratedToken token = tokenProvider.generateToken(
                subject,
                builder -> builder.claim("roles", List.of("ADMIN"))
        );
        return AuthResponse.from(token);
    }
}
```

---

## Receiving the authenticated principal

The token subject is set as the principal in the security context.

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(
            @AuthenticationPrincipal Object principal
    ) {
        UUID id = UUID.fromString(principal.toString());
        return ResponseEntity.ok(userService.findById(id));
    }
}
```

---

## Overriding beans

All beans are declared with `@ConditionalOnMissingBean`, allowing full customization:

- `TokenProvider` / `JwtTokenProvider`
- `TokenAuthenticationConverter`
- `JwtAuthenticationFilter`

---

## License

This project is licensed under [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html).

See [LICENSE](LICENSE) file for details.