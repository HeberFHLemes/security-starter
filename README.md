# security-starter

JWT-based stateless authentication for Spring Boot

[![CI/CD Pipeline](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.heberfhlemes/security-starter)](https://search.maven.org/artifact/io.github.heberfhlemes/security-starter)
![License](https://img.shields.io/github/license/HeberFHLemes/security-starter)

A Spring Boot starter to simplify **Spring Security configuration** for JWT-based stateless authentication.
It abstracts JWT authentication logic, reducing boilerplate code and offering some interfaces to guide the
implementation.

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
    <version>0.3.2</version>
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

### JwtSecurityConfigurer

You can use this utility class in your security configuration to set your authentication flow to stateless, applying a
filter.

```java
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {
    
    private final JwtAuthenticationFilter jwtFilter;
    
    // ...

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        JwtSecurityConfigurer.applyTo(http, jwtFilter);

        return http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .build();
    }
}
```

### Disabling UserDetailsServiceAutoConfiguration

```java
@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### Using a TokenProvider implementation

Generate and validate tokens:

```java
@Service
public class AuthService {

    private final JwtTokenProvider tokenProvider;

    // ...

    public AuthResponse login(LoginRequest request) {
        User user = findUser(request);
        GeneratedToken token = tokenProvider.generateToken(
                userSubject, // your token subject
                jwtBuilder -> jwtBuilder // custom claims
                        .issuer("...")
                        .claim("role", "...")
        );
        return AuthResponse.from(token);
    }
    
    public void validateToken(String tokenString) {
        // Already done inside the JWT filter.
        // Use when you want a custom filter implementation 
        // or additional validation logic.
        TokenValidationResult result = tokenProvider.validate(tokenString);
        if (!result.valid()) {
            throw new InvalidTokenException("Token validation failed");
        }
    }
}
```

### Receiving authenticated user

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    // ...
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(
            @AuthenticationPrincipal Object principal
    ) {
        UUID id = UUID.fromString(principal.toString());
        return ResponseEntity.ok(UserResponse.from(userService.findById(id)));
    }
}
```

---

## Overriding beans

All beans are declared with `@ConditionalOnMissingBean`, allowing full customization:

- `JwtTokenProvider`
- `JwtAuthenticationConverter`
- `JwtAuthenticationFilter`

---

## License

This project is licensed under [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html).

See [LICENSE](LICENSE) file for details.
