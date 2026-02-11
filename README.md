# Security Starter

JWT-based stateless authentication for Spring Boot

[![CI/CD Pipeline](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/HeberFHLemes/security-starter/actions/workflows/ci.yml) 
[![Maven Central](https://img.shields.io/maven-central/v/io.github.heberfhlemes/security-starter)](https://search.maven.org/artifact/io.github.heberfhlemes/security-starter)
![License](https://img.shields.io/github/license/HeberFHLemes/security-starter)

A Spring Boot starter to simplify **Spring Security configuration** for JWT-based stateless authentication.

This library is designed to **abstract JWT authentication logic** while keeping your application modular and decoupled 
from infrastructure.

---

## Requirements

- Spring Boot 4.x
- Spring Security (`spring-boot-starter-security`)
- Spring Web (`spring-boot-starter-web`)
- Do not expose user passwords

> **Note:** The starter relies on Spring Security and a runtime implementation of the Jakarta Servlet API (usually included via Spring Web).

---

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>io.github.heberfhlemes</groupId>
  <artifactId>security-starter</artifactId>
  <version>0.3.0</version>
</dependency>
```

---

### Configuration

#### JWT Properties
In your `application.properties` or `application.yml`:
```yaml
securitystarter:
  jwt:
    secret: ${JWT_SECRET}
    expiration: 720000 # in milliseconds
```

#### SecurityConfigurationSupport
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

#### Creating a custom UserDetailsService implementation

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

#### Using TokenProvider
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

### Overriding Beans
All core beans are declared with `@ConditionalOnMissingBean`, allowing you to provide 
custom implementations:

- `PasswordEncoder`
- `TokenProvider`
- `JwtAuthenticationConverter`
- `JwtAuthenticationFilter`
- `TokenAuthenticationService`

This starter provides token-based authentication infrastructure only and does not include
authentication controllers, route definitions, or user persistence.

---

### License

This project is licensed under [Apache License, Version 2.0.](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.
