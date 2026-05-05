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
package io.github.heberfhlemes.securitystarter.core;

import java.util.Collection;
import java.util.List;

/**
 * Provides typed access to token claims by name.
 *
 * @author Héber F. H. Lemes
 * @since 0.4.0
 */
public interface TokenClaims {

    /**
     * Returns the raw value of the claim with the given name.
     *
     * @param name the claim name
     * @return the raw claim value, or {@code null} if absent
     */
    Object get(String name);

    /**
     * Returns the claim value as a {@link String}.
     *
     * @param name the claim name
     * @return the string representation of the value,
     * or {@code null} if the claim is absent
     */
    default String getString(String name) {
        Object value = get(name);
        return value != null ? value.toString() : null;
    }

    /**
     * Returns the claim value as a list of strings.
     *
     * <p>If the claim value is a {@link Collection}, each element
     * is converted via {@code toString()}. Returns an empty list
     * if the claim is absent or not a collection.</p>
     *
     * @param name the claim name
     * @return a list of string values, never {@code null}
     */
    default List<String> getList(String name) {
        Object value = get(name);
        if (value instanceof Collection<?> c) {
            return c.stream().map(Object::toString).toList();
        }
        return List.of();
    }

    /**
     * Returns the claim value as a {@link Boolean}.
     *
     * @param name the claim name
     * @return the boolean value, or {@code null} if absent or not a boolean
     */
    default Boolean getBoolean(String name) {
        Object value = get(name);
        return value instanceof Boolean b ? b : null;
    }

    /**
     * Returns the claim value as a {@link Long}.
     *
     * <p>Any number value is converted via {@code longValue()}.</p>
     *
     * @param name the claim name
     * @return the long value, or {@code null} if absent or not a number
     */
    default Long getLong(String name) {
        Object value = get(name);
        return value instanceof Number n ? n.longValue() : null;
    }

    /**
     * Returns whether a claim with the given name is present and non-null.
     *
     * @param name the claim name
     * @return {@code true} if the claim exists and is non-null
     */
    default boolean has(String name) {
        return get(name) != null;
    }

    /**
     * Returns an empty {@link TokenClaims} instance with no claims.
     *
     * @return a singleton empty instance
     */
    static TokenClaims empty() {
        return EmptyTokenClaims.INSTANCE;
    }

    final class EmptyTokenClaims implements TokenClaims {
        private static final EmptyTokenClaims INSTANCE = new EmptyTokenClaims();

        private EmptyTokenClaims() {
        }

        @Override
        public Object get(String name) {
            return null;
        }
    }
}
