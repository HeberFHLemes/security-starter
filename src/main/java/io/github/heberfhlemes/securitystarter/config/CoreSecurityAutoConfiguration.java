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

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Autoconfiguration for the core security components provided by the
 * {@code security-starter}. This class registers the minimum required beans
 * for password handling and authentication unless the application defines its
 * own overrides.
 *
 * <p>This configuration provides:</p>
 * <ul>
 *   <li>{@link org.springframework.security.crypto.password.PasswordEncoder}
 *       — a default {@link DelegatingPasswordEncoder}, overridable by defining another bean.</li>
 * </ul>
 *
 * <p>
 *     Users may override any provided bean by defining one with the same type.
 * </p>
 *
 * @author Héber F. H. Lemes
 * @since 0.1.0
 */
@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class CoreSecurityAutoConfiguration {

    /**
     * Registers a default {@link PasswordEncoder} using {@link DelegatingPasswordEncoder}.
     * <p>
     * Applications may override this bean if a different password hashing strategy
     * is required.
     * </p>
     *
     * @return the {@link DelegatingPasswordEncoder} to use
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
