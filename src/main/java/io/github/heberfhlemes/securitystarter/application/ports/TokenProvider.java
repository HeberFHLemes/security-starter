package io.github.heberfhlemes.securitystarter.application.ports;

public interface TokenProvider {

    String generateToken(String subject);

    boolean validateToken(String token, String subject);

    String extractSubject(String token);

}
