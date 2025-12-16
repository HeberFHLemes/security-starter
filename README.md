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
This is entirely optional, but you can extend `SecurityConfigurationSupport` to define route authorization policies 
while already having some common logic in your security configuration class.

```java
@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends SecurityConfigurationSupport {

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
        configureCommonSecurity(http, jwtFilter); // from SecurityConfigurationSupport class
        configureAuthorization(http.authorizeHttpRequests());
        return http.build();
    }
}
```

#### Using JwtAuthenticationService
Generate and validate tokens in your controllers or services:

```java
import io.github.heberfhlemes.securitystarter.application.services.TokenAuthenticationService;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class MyClass {

    private final TokenAuthenticationService authenticationService;
    private final UserDetailsService userDetailsService;

    public MyClass(TokenAuthenticationService authenticationService,
                   UserDetailsService userDetailsService) {
        this.authenticationService = authenticationService;
        this.userDetailsService = userDetailsService;
    }

    public void someMethod() {
        UserDetails userDetails = userDetailsService.loadUserByUsername("username");

        String token = authenticationService.generateToken(userDetails);
        boolean valid = authenticationService.validateToken(token, userDetails.getUsername());
    }
}
```

---

### Overriding Beans
All core beans are `@ConditionalOnMissingBean`, so you can provide your own implementations:

- `PasswordEncoder`
- `AuthenticationProvider`
- `AuthenticationManager`
- `JwtTokenProvider`
- `JwtAuthenticationFilter`
- `TokenAuthenticationService`

---

### License

This project is licensed under [Apache License, Version 2.0.](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.

