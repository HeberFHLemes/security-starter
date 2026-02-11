package io.github.heberfhlemes.securitystarter.filters;

import io.github.heberfhlemes.securitystarter.application.ports.JwtAuthenticationConverter;
import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.github.heberfhlemes.securitystarter.application.token.TokenValidationResult;
import io.github.heberfhlemes.securitystarter.infrastructure.filters.JwtAuthenticationFilter;
import io.github.heberfhlemes.securitystarter.infrastructure.jwt.UserDetailsJwtAuthenticationConverter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Instant;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import static org.junit.jupiter.api.Assertions.assertNull;

class JwtAuthenticationFilterTest {

    private TokenProvider tokenProvider;
    private UserDetailsService userDetailsService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setup() {
        tokenProvider = mock(TokenProvider.class);
        userDetailsService = mock(UserDetailsService.class);

        JwtAuthenticationConverter converter =
                new UserDetailsJwtAuthenticationConverter(userDetailsService);

        filter = new JwtAuthenticationFilter(tokenProvider, converter);

        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticateValidToken() throws Exception {
        String token = "valid.jwt.token";
        String username = "user_1";

        when(tokenProvider.validate(token)).thenReturn(
                new TokenValidationResult(
                        true,
                        username,
                        Instant.now().plusSeconds(600)
                )
        );

        UserDetails user = User.withUsername(username)
                .password("pass")
                .roles("USER")
                .build();

        when(userDetailsService.loadUserByUsername(username))
                .thenReturn(user);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNotNull();
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getName()).isEqualTo(username);
        assertThat(Objects.requireNonNull(authentication.getPrincipal())).isEqualTo(user);

        verify(tokenProvider).validate(token);
        verify(userDetailsService).loadUserByUsername(username);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateWhenTokenIsInvalid() throws Exception {
        String token = "invalid.jwt.token";

        when(tokenProvider.validate(token))
                .thenReturn(new TokenValidationResult(false, null, null));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(tokenProvider).validate(token);
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void shouldNotAuthenticateWhenSubjectIsMissing() throws Exception {
        String token = "jwt.without.subject";

        when(tokenProvider.validate(token))
                .thenReturn(new TokenValidationResult(true, null, null));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(tokenProvider).validate(token);
        verify(userDetailsService, never()).loadUserByUsername(any());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void shouldIgnoreWhenAuthorizationHeaderIsMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verifyNoInteractions(tokenProvider, userDetailsService);
        verify(chain).doFilter(any(), any());
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

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("existing");

        verifyNoInteractions(tokenProvider, userDetailsService);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void shouldNotAuthenticateWhenUserDoesNotExist() throws Exception {
        String token = "valid.jwt.token";
        String username = "ghost";

        when(tokenProvider.validate(token))
                .thenReturn(new TokenValidationResult(true, username, null));

        when(userDetailsService.loadUserByUsername(username))
                .thenThrow(new UsernameNotFoundException("not found"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(tokenProvider).validate(token);
        verify(userDetailsService).loadUserByUsername(username);
        verify(chain).doFilter(any(), any());
    }
}
