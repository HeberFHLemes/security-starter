package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import io.github.heberfhlemes.securitystarter.application.ports.TokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JwtTokenProvider implements TokenProvider {

    private final JwtProperties properties;
    private final SecretKey signingKey;

    public JwtTokenProvider(JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(
                properties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    private SecretKey getSignKey() {
        return this.signingKey;
    }

    /**
     * Generates a JWT token considering a given username.
     * @param subject Subject to use it into token creation
     * @return Created token.
     */
    public String generateToken(String subject) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, subject);
    }

    /**
     * Creates token with claims and subject (username).
     * @param claims JWT Claims.
     * @param subject JWT Subject, in this case, username.
     * @return Created token.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Instant now = Instant.now();

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(properties.getExpiration())))
                .signWith(getSignKey())
                .compact();
    }

    /**
     * Extracts username from a given token
     * @param token JWT Token
     * @return Claim extracted
     */
    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts expiration date from token
     * @param token Token to be extracted
     * @return Token's expiration date
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracts a specific claim from token.
     * @param token JWT token
     * @param claimsResolver a function to resolve claim (like in {@code Claims::getSubject})
     * @return the result of the function {@code apply(claims)} from claimsResolver.
     * @param <T> the type of the result of the function
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from given token
     * @param token JWT token
     * @return All claims extracted from the token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifies if token is expired
     * @param token JWT token
     * @return {@code true} if the expiration time is strictly earlier than actual time
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    public boolean validateToken(String token, String subject) {
        final String extractedUsername = extractSubject(token);
        return (extractedUsername.equals(subject) && !isTokenExpired(token));
    }
}
