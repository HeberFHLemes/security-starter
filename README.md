# Security Starter

A Spring Boot starter to simplify **Spring Security configuration** for JWT-based stateless authentication.

This library is designed to **abstract JWT authentication logic**, while keeping your application modular and decoupled from infrastructure.

---

## Requirements

- Spring Boot 4.x
- Spring Security (`spring-boot-starter-security`)
- Spring Web (`spring-boot-starter-web`)
- Do not expose user passwords :)

> **Note:** The starter relies on Spring Security and a runtime implementation of the Jakarta Servlet API (usually included via Spring Web).

---

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>io.github.heberfhlemes</groupId>
  <artifactId>security-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

---

### Configuration

#### JWT Properties
In your `application.properties` or `application.yml`:
```yaml
jwt:
  secret: your-secret-key
  expiration: 720000 # in ms
```

#### SecurityConfigurer
This is entirely optional, but you can extend `SecurityConfigurer` to define route authorization policies 
while already having some common logic in your security configuration class.

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends SecurityConfigurer {

    @Override
    protected void configureAuthorization(AuthorizeHttpRequestsConfigurer<HttpSecurity>
                                                      .AuthorizationManagerRequestMatcherRegistry auth) {
        auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
        configureCommonSecurity(http, jwtFilter); // from SecurityConfigurer class
        configureAuthorization(http.authorizeHttpRequests());
        return http.build();
    }
}
```

#### Using JwtAuthenticationService
Generate and validate tokens in your controllers or services:

```java
@Autowired
private JwtAuthenticationService jwtAuthService;

String token = jwtAuthService.generateToken(userDetails);
boolean valid = jwtAuthService.validateToken(token, userDetails.getUsername());
```

---

### Overriding Beans
All core beans are `@ConditionalOnMissingBean`, so you can provide your own implementations:

- `PasswordEncoder`
- `AuthenticationProvider`
- `AuthenticationManager`
- `JwtService`
- `JwtAuthenticationFilter`
- `JwtAuthenticationService`

---

### License

This project is licensed under [Apache License, Version 2.0.](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.

