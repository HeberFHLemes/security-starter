# security-starter

Project to help developers of Spring Boot applications to configure Spring Security configuration.

In this first version, the goal is to abstract JWT authentication logic.

---

### Requirements
- Spring Boot 4.x version
- Spring Security
- Spring Web
- Do not expose user password :)

---

### Installation
In your project's `pom.xml` (if using Maven):
```xml
<dependency>
  <groupId>io.github.heberfhlemes</groupId>
  <artifactId>security-starter</artifactIf>
  <version>1.0.0</version>
</dependency>
```

---

### Configuration
In your project's `application.properties` (or YAML), set the JWT secret
value and jwt expiration value.

Then, implement the interface `UserDetailsService`, configure your security configuration
(its routes policies, etc.) implementing the interface `SecurityConfigurer`, and use
`AuthService` in your controller class to validate or generate tokens.

It is that simple!

---

### License

This project is licensed under [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0.html)

See [LICENSE](LICENSE) file for details.

