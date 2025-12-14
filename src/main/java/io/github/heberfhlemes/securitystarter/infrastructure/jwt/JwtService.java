package io.github.heberfhlemes.securitystarter.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JwtService {

    private final JwtProperties properties;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
    }

    /**
     * Generates a JWT token considering a given username.
     * @param username User's username.
     * @return Created token.
     */
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    /**
     * Creates token with claims and subject (username).
     * @param claims JWT Claims.
     * @param subject JWT Subject, in this case, username.
     * @return Created token.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(now))
                .expiration(new Date(now + properties.getExpiration()))
                .signWith(getSignKey())
                .compact();
    }

    private SecretKey getSignKey() {
        return Keys.hmacShaKeyFor(
                properties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Extracts username from a given token
     * @param token JWT Token
     * @return Claim extracted
     */
    // Extrai username do token
    public String extractUsername(String token) {
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
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Validates token
     * @param token JWT token
     * @param username User's username
     * @return {@code true} if username matches with subject and token is not expired.
     */
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}
