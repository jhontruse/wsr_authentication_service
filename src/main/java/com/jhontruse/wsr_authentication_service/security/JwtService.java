package com.jhontruse.wsr_authentication_service.security;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${security.jwt.secret.key}") // Expression Language ${}
    private String secret;

    @Value("${security.jwt.expiration}") // Expression Language ${}
    private Long JWT_TOKEN_VALIDITY;

    @Value("${security.jwt.refresh.expiration}")
    private Long REFRESH_TOKEN_EXPIRATION;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Value("${security.jwt.secret-base64}")
    private String secretBase64;

    @Value("${security.jwt.key}")
    private String k1;

    private String doGenerateToken(Map<String, Object> claims, String username, Long expirationTime) {
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - doGenerateToken");
        log.info("********************************");
        log.info("********************************");
        log.info("claims: {}", claims);
        log.info("username: {}", username);
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretBase64.trim()));
        log.info("key: {}", key);
        return Jwts.builder()
                .header().type("JWT").keyId(k1).and()
                .issuer(issuer)
                .claims(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key, Jwts.SIG.HS256)
                .notBefore(new Date(System.currentTimeMillis() - 5000)) // nbf
                .id(UUID.randomUUID().toString()) // jti
                .audience().add("web").and() // aud
                .claim("typ", "ACCESS")
                .compact();
    }

    public String generateToken(UserDetails userDetails, List<String> menus) {
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - generateToken");
        log.info("********************************");
        log.info("********************************");
        log.info("userDetails: {}", userDetails);
        log.info("menus: {}", menus);
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","))); // ADMIN,USER,DBA
        // claims.put("usuario", userDetails.getUsername());
        claims.put("menu", menus);
        log.info("claims: {}", claims);
        return doGenerateToken(claims, userDetails.getUsername(), JWT_TOKEN_VALIDITY);
    }

    public String generateRefreshToken(UserDetails userDetails, List<String> menus) {
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - generateRefreshToken");
        log.info("********************************");
        log.info("********************************");
        log.info("userDetails: {}", userDetails);
        log.info("menus: {}", menus);
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","))); // ADMIN,USER,DBA
        // claims.put("usuario", userDetails.getUsername());
        claims.put("menu", menus);
        log.info("claims: {}", claims);
        return doGenerateToken(claims, userDetails.getUsername(), REFRESH_TOKEN_EXPIRATION);
    }

    public Claims getAllClaimsFromToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretBase64.trim()));
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - getAllClaimsFromToken");
        log.info("********************************");
        log.info("********************************");
        log.info("key: {}", key);
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - getClaimFromToken");
        log.info("********************************");
        log.info("********************************");
        log.info("token: {}", token);
        log.info("claimsResolver: {}", claimsResolver);
        return claimsResolver.apply(claims);
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - isTokenExpired");
        log.info("********************************");
        log.info("********************************");
        log.info("token: {}", token);
        log.info("expiration: {}", expiration);
        return expiration.before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        log.info("********************************");
        log.info("********************************");
        log.info("JwtService - validateToken");
        log.info("********************************");
        log.info("********************************");
        log.info("token: {}", token);
        log.info("userDetails: {}", userDetails);
        log.info("username: {}", username);
        return (username.equalsIgnoreCase(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
