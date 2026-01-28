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
  <version>0.2.0</version>
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
    
    // Other desired beans
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
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
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> 
                new UsernameNotFoundException("User not found: " + username));

        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }
}
```

#### Using TokenAuthenticationService
Generate and validate tokens in your controllers or services:

```java
@RestController
@RequestMapping("/api/auth")
public class TestAuthController {

    private final TokenAuthenticationService authService;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public TestAuthController(TokenAuthenticationService authService,
                              AuthenticationManager authenticationManager,
                              UserService userService) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@Valid @RequestBody LoginDTO loginDTO) {
        return ResponseEntity.ok(
                userService.saveUser(loginDTO.username(), loginDTO.password())
        );
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginDTO loginDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDTO.username(),
                        loginDTO.password()
                )
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = authService.generateToken(userDetails);
        
        return ResponseEntity.ok(new AuthResponseDTO(token, "Login successful"));
    }
}
```

---

### Overriding Beans
All core beans are `@ConditionalOnMissingBean`, so you can provide your own implementations:

- `PasswordEncoder`
- `TokenProvider`
- `JwtAuthenticationConverter`
- `JwtAuthenticationFilter`
- `TokenAuthenticationService`

---

### What this starter does NOT do

- Does not provide authentication controllers (login/register)
- Does not define application routes
- Does not store users or credentials

---

### License

This project is licensed under [Apache License, Version 2.0.](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.
