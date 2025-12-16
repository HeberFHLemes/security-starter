package io.github.heberfhlemes.securitystarter.config;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class CoreSecurityAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreSecurityAutoConfiguration.class));

    @Test
    void shouldAutoConfigureAllBeans() {
        contextRunner
            .withBean(UserDetailsService.class, () -> Mockito.mock(UserDetailsService.class))
            .withBean(AuthenticationConfiguration.class, this::mockAuthenticationConfiguration)
            .run(context -> {
                assertThat(context).hasSingleBean(PasswordEncoder.class);
                assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(BCryptPasswordEncoder.class);

                assertThat(context).hasSingleBean(AuthenticationProvider.class);
                assertThat(context.getBean(AuthenticationProvider.class)).isInstanceOf(DaoAuthenticationProvider.class);

                assertThat(context).hasSingleBean(AuthenticationManager.class);
            });
    }

    @Test
    void shouldUseCustomBeansWhenPresent() {
        contextRunner
            .withBean(UserDetailsService.class, () -> Mockito.mock(UserDetailsService.class))
            .withBean(AuthenticationConfiguration.class, this::mockAuthenticationConfiguration)
            .withUserConfiguration(CustomBeansConfig.class)
            .run(context -> {
                assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(CustomPasswordEncoder.class);
                assertThat(context.getBean(AuthenticationProvider.class)).isInstanceOf(CustomAuthenticationProvider.class);
                assertThat(context.getBean(AuthenticationManager.class)).isInstanceOf(CustomAuthenticationManager.class);
            });
    }

    @Test
    void shouldNotAutoConfigureWhenSecurityFilterChainIsMissing() {
        contextRunner
            .withClassLoader(new FilteredClassLoader(org.springframework.security.web.SecurityFilterChain.class))
            .withBean(UserDetailsService.class, () -> Mockito.mock(UserDetailsService.class))
            .withBean(AuthenticationConfiguration.class, this::mockAuthenticationConfiguration)
            .run(context -> {
                assertThat(context).doesNotHaveBean(PasswordEncoder.class);
                assertThat(context).doesNotHaveBean(AuthenticationProvider.class);
                assertThat(context).doesNotHaveBean(AuthenticationManager.class);
            });
    }

    private AuthenticationConfiguration mockAuthenticationConfiguration() {
        AuthenticationConfiguration config = Mockito.mock(AuthenticationConfiguration.class);
        AuthenticationManager manager = Mockito.mock(AuthenticationManager.class);
        Mockito.when(config.getAuthenticationManager()).thenReturn(manager);
        return config;
    }

    @Configuration
    static class CustomBeansConfig {
        @Bean PasswordEncoder passwordEncoder() { return new CustomPasswordEncoder(); }
        @Bean AuthenticationProvider authenticationProvider() { return new CustomAuthenticationProvider(); }
        @Bean AuthenticationManager authenticationManager() { return new CustomAuthenticationManager(); }
    }

    static class CustomPasswordEncoder implements PasswordEncoder {
        @Override public String encode(CharSequence rawPassword) { return "custom:" + rawPassword; }
        @Override public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return ("custom:" + rawPassword).equals(encodedPassword);
        }
    }

    static class CustomAuthenticationProvider implements AuthenticationProvider {
        @Override public org.springframework.security.core.Authentication authenticate(org.springframework.security.core.Authentication authentication) {
            return authentication;
        }
        @Override public boolean supports(Class<?> authentication) { return true; }
    }

    static class CustomAuthenticationManager implements AuthenticationManager {
        @Override public org.springframework.security.core.Authentication authenticate(org.springframework.security.core.Authentication authentication) {
            return authentication;
        }
    }
}