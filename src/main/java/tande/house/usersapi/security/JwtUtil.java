package tande.house.usersapi.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.ttlSeconds:604800}")
    private long ttlSeconds;

    public String createToken(Long userId, String email, boolean admin) {
        long now = System.currentTimeMillis();
        long exp = now + ttlSeconds * 1000L;

        return Jwts.builder()
                .issuer(issuer)
                .subject(String.valueOf(userId))
                .claims(Map.of(
                        "email", email,
                        "admin", admin
                ))
                .issuedAt(new Date(now))
                .expiration(new Date(exp))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public UserPrincipal verify(String token) {
        var claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Long userId = Long.parseLong(claims.getSubject());
        String email = String.valueOf(claims.get("email"));
        boolean admin = Boolean.parseBoolean(String.valueOf(claims.get("admin")));

        return new UserPrincipal(userId, email, admin);
    }
}
