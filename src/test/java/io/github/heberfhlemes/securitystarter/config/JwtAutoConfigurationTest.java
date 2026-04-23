/*
 * Copyright 2025 Héber F. H. Lemes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.heberfhlemes.securitystarter.config;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class));

    private ApplicationContextRunner withValidJwtProperties() {
        return contextRunner.withPropertyValues(
                "securitystarter.jwt.secret=example-of-long-jwt-secret-in-properties",
                "securitystarter.jwt.expiration=PT1H"
        );
    }

    @Test
    void shouldNotLoadWhenSecurityIsMissing() {
        contextRunner
                .withClassLoader(new FilteredClassLoader(SecurityFilterChain.class))
                .run(context -> {
                    assertThat(context).doesNotHaveBean(TokenProvider.class);
                    assertThat(context).doesNotHaveBean(OncePerRequestFilter.class);
                });
    }

    @Test
    void shouldRegisterJwtBeans() {
        withValidJwtProperties()
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenProvider.class);
                    assertThat(context).hasSingleBean(OncePerRequestFilter.class);
                    assertThat(context.getBean(TokenProvider.class))
                            .isInstanceOf(JwtTokenProvider.class);
                });
    }

    @Test
    void shouldNotOverrideUserProvidedTokenProvider() {
        TokenProvider userProvided = Mockito.mock(TokenProvider.class);

        withValidJwtProperties()
                .withBean(TokenProvider.class, () -> userProvided)
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenProvider.class);
                    assertThat(context.getBean(TokenProvider.class))
                            .isSameAs(userProvided);
                });
    }

    @Test
    void failsWhenSecretIsMissing() {
        contextRunner
                .withPropertyValues("securitystarter.jwt.expiration=PT1H")
                .run(context -> {
                    Throwable failure = context.getStartupFailure();

                    assertThat(failure)
                            .isNotNull()
                            .hasRootCauseInstanceOf(IllegalArgumentException.class);
                });
    }

    @Test
    void failsWhenJwtSecretIsTooShort() {
        contextRunner
                .withPropertyValues(
                        "securitystarter.jwt.secret=short-secret",
                        "securitystarter.jwt.expiration=PT1H"
                )
                .run(context -> {
                    Throwable failure = context.getStartupFailure();

                    assertThat(failure)
                            .hasRootCauseInstanceOf(IllegalArgumentException.class);
                });
    }

}
