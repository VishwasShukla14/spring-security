package com.vishwas.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Key for digitally signing the jwt token.
    // Generated from https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx
    private static final String SECRET_KEY = "462D4A404E635266556A586E3272357538782F413F4428472B4B625064536756";

    // Generating a user-specific token.
    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        return Jwts.builder().setClaims(extraClaims).
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date(System.currentTimeMillis())).
                setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 24)).
                signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Generate an empty/default token
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    // Extracting the username form the token
    // In claim/payload the username is identified by subject
    public String extractUserName(String token){
        return getClaims(token,Claims::getSubject);
    }

    // checking if the token is valid or not
    public boolean isTokenValid(String token,UserDetails userDetails){
        String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Fetching a particular claim
    public <T> T getClaims(String token, Function<Claims,T> extractClaim){
        Claims claims = getAllClaims(token);
        return extractClaim.apply(claims);
    }

    //  Fetching all claims/payload from the header
    private Claims getAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Extracting the expiration date.
    private Date extractExpiration(String token) {
        return getClaims(token,Claims::getExpiration);
    }

    // Checking if the token is expired or not
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Return the signed key using the SECRET_KEY
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
