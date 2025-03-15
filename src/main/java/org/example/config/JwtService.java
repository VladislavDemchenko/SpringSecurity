package org.example.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String SECRET_KEY = "dHJhY2t2aWN0b3J5c3VnYXJ0aGVyZWZlYXRoZXJzY2xvdGhlYXJsaWVyaGFyYm9yZmlmdGhtb3ZlbWVudG1lZGljaW5lc3VwcG9zZW1vbnRocGllY2VzdXJmYWNldHJvcGljYWxzeW1ib2xiZWxpZXZlZGF3YXJlY2xvdWRzeXN0ZW1hbmdyeWV2ZXJ5d2hlcmVjb3BwZXJjb21tb25icmVha2Zhc3RzYWlsY29uc2lzdGRyaXZlbmVhc2lseXJlbW92ZWNoYXJhY3RlcmR1bGxlbnRpcmViZWluZ21hbnVmYWN0dXJpbmd0YWtlbGVnc2hvZWNob29zZXR5cGljYWxicm9rZW51bml0c2F3aGltYnJvd25wb3NpdGlvbmV2ZXJ5dGhpbmdjaGFwdGVybWVhbnRjdXJpb3VzaGFuZHNvbWVuZXh0Z2V0dGluZ3BhcnRpY3VsYXJseXNsZWVwd2lzaGxpdHRsZXNvdXRoY2hhaXJzYW1laWZwaHlzaWNhbGZyb210aG91c2FuZGNyYWNrY2xvdGhpbmdzbG93bHllcXVhdG9ybG90ZW5qb3ltYXRlcmlhbGJyaWdodGNyeXJlYWxpemVzaW1wbGVzcXVhcmVoYWJpdHdyaXRlcmZvcmdvdGxlYWRlcmNhcnJ5Y2h1cmNobW9zdGF0ZXJheXM=";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

	public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey())
                .compact();
    }

	public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
    }

}
