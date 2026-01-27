package io.github.heberfhlemes.securitystarter.config;

import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class CoreSecurityAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreSecurityAutoConfiguration.class));

    @Test
    void shouldAutoConfigureAllBeans() {
        contextRunner
            .run(context -> {
                assertThat(context).hasSingleBean(PasswordEncoder.class);
                assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(BCryptPasswordEncoder.class);
            });
    }

    @Test
    void shouldUseCustomBeansWhenPresent() {
        contextRunner
            .withUserConfiguration(CustomBeansConfig.class)
            .run(context ->
                    assertThat(context.getBean(PasswordEncoder.class))
                            .isInstanceOf(CustomPasswordEncoder.class));
    }

    @Test
    void shouldNotAutoConfigureWhenSecurityFilterChainIsMissing() {
        contextRunner
            .withClassLoader(new FilteredClassLoader(org.springframework.security.web.SecurityFilterChain.class))
            .run(context ->
                assertThat(context)
                        .doesNotHaveBean(PasswordEncoder.class)
            );
    }

    @Configuration
    static class CustomBeansConfig {
        @Bean PasswordEncoder passwordEncoder() { return new CustomPasswordEncoder(); }
    }

    static class CustomPasswordEncoder implements PasswordEncoder {
        @Override public String encode(CharSequence rawPassword) { return "custom:" + rawPassword; }
        @Override public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return ("custom:" + rawPassword).equals(encodedPassword);
        }
    }
}