package io.github.heberfhlemes.securitystarter.filters;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.JwtTokenProvider;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private TokenProvider tokenProvider;
    private UserDetailsService userDetailsService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setup() {
        tokenProvider = Mockito.mock(TokenProvider.class);
        userDetailsService = Mockito.mock(UserDetailsService.class);
        filter = new JwtAuthenticationFilter(tokenProvider, userDetailsService);

        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticateValidToken() throws Exception {
        String token = "valid.jwt.token";
        String username = "user_1";

        // Arrange
        when(tokenProvider.extractSubject(token)).thenReturn(username);
        when(tokenProvider.validateToken(token, username)).thenReturn(true);

        UserDetails user = User.withUsername(username)
                .password("pass")
                .roles("USER")
                .build();

        when(userDetailsService.loadUserByUsername(username))
                .thenReturn(user);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = Mockito.mock(FilterChain.class);

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertInstanceOf(UsernamePasswordAuthenticationToken.class, authentication);
        assertTrue(authentication.isAuthenticated());
        assertEquals(username, authentication.getName());

        verify(filterChain).doFilter(request, response);
        verify(tokenProvider).extractSubject(token);
        verify(tokenProvider).validateToken(token, username);
        verify(userDetailsService).loadUserByUsername(username);
    }
}
