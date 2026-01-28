package io.github.heberfhlemes.securitystarter.filters;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;

import io.github.heberfhlemes.securitystarter.infrastructure.jwt.UserDetailsJwtAuthenticationConverter;
import jakarta.servlet.FilterChain;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private TokenProvider tokenProvider;
    private UserDetailsService userDetailsService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setup() {
        tokenProvider = mock(TokenProvider.class);
        userDetailsService = mock(UserDetailsService.class);

        JwtAuthenticationConverter authenticationConverter =
                new UserDetailsJwtAuthenticationConverter(userDetailsService);

        filter = new JwtAuthenticationFilter(tokenProvider, authenticationConverter);

        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticateValidToken() throws Exception {
        String token = "valid.jwt.token";
        String username = "user_1";

        // Arrange
        when(tokenProvider.validateToken(token)).thenReturn(true);
        when(tokenProvider.extractSubject(token)).thenReturn(username);

        UserDetails user = User.withUsername(username)
                .password("pass")
                .roles("USER")
                .build();

        when(userDetailsService.loadUserByUsername(username))
                .thenReturn(user);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = mock(FilterChain.class);

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNotNull();
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getName()).isEqualTo(username);

        Object principal = authentication.getPrincipal();
        assertThat(principal).isEqualTo(user);

        verify(filterChain).doFilter(request, response);
        verify(tokenProvider).validateToken(token);
        verify(tokenProvider).extractSubject(token);
        verify(userDetailsService).loadUserByUsername(username);
    }

    @Test
    void shouldNotAuthenticateWhenTokenIsInvalid() throws Exception {
        String token = "invalid.jwt.token";
        String username = "user_1";

        // Arrange
        when(tokenProvider.extractSubject(token)).thenReturn(username);
        when(tokenProvider.validateToken(token)).thenReturn(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNull();
        verify(filterChain).doFilter(request, response);

        verify(tokenProvider).validateToken(token);
        verify(tokenProvider, never()).extractSubject(token);

        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    void shouldNotAuthenticateWhenTokenHasNoSubject() throws Exception {
        String token = "jwt.without.subject";

        when(tokenProvider.validateToken(token)).thenReturn(true);
        when(tokenProvider.extractSubject(token)).thenReturn(null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(filterChain).doFilter(request, response);
        verify(tokenProvider).validateToken(token);
        verify(tokenProvider).extractSubject(token);
        verify(userDetailsService, never()).loadUserByUsername(any());
    }

    @Test
    void shouldIgnoreWhenAuthorizationHeaderIsMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = mock(FilterChain.class);
        filter.doFilter(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(tokenProvider, userDetailsService);
    }

    @Test
    void shouldNotOverrideExistingAuthentication() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("existing", null)
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer some.token");

        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("existing");

        verify(chain).doFilter(any(), any());
        verifyNoInteractions(tokenProvider, userDetailsService);
    }

    @Test
    void shouldNotAuthenticateWhenUserDoesNotExist() throws Exception {
        String token = "valid.jwt.token";
        String username = "ghost";

        when(tokenProvider.validateToken(token)).thenReturn(true);
        when(tokenProvider.extractSubject(token)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username))
                .thenThrow(new UsernameNotFoundException("not found"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
        assertThat(authentication).isNull();

        verify(chain).doFilter(any(), any());
        verify(tokenProvider).validateToken(token);
        verify(tokenProvider).extractSubject(token);
        verify(userDetailsService).loadUserByUsername(username);
    }
}
