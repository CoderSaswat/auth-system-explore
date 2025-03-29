package com.abc.spring.security.utils;

import com.abc.spring.security.dto.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    //openssl rand -base64 256 (git bash)
    private final String SECRET_KEY = "k7Sa+LTeMwbP+m9djgPOfdEDnKnrPZdjM+n1Gt1QfxFIZqzz0A3cMsB08FhP+3r5WHr7kvtF1Vcd1WB7aEorm7sfIexTGndTatO7UYXspMwpbTYPJ/UJqdXvUDUQUmdpSESkY1iAmy/qzd+pNyTrLwmoGao4f/kJZRTqosyVEi8csZlW3mMe/F2zXT1/yfmQmo1myiHGQWk5vd/G2wPXbKLK/q9JcaodKKRDsgMXsmwjKddIRfxzO56Ehx6ga9OhSOi1HJRVm1cLAgGZhQNH9vuug//w4B6s46r23U2D5zLwBroa31FOCAId1nDNFdpuMh7Jo2sKZ+z2LnNr7XAhDg==";

    public Key getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
    }

    // Generate Token
    public String generateToken(UserDetails userDetails) {
        Set<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        Long userId = ((CustomUserDetails) userDetails).getUserId();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("authorities", authorities)
                .claim("username", userDetails.getUsername())
                .claim("userId", userId)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .setIssuedAt(new Date())
                .signWith(getSigningKey())
                .compact();
    }

    // Extract Username from Token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // Extract Claims
    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningKey())
                .parseClaimsJws(token)
                .getBody();
    }

    // Validate Token
    public boolean validateToken(String token, String username) {
        return extractUsername(token).equals(username) && !isTokenExpired(token);
    }

    // Check if Token is Expired
    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
