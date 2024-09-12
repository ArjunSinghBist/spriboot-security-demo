package com.scaler.security.config;

import com.scaler.security.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JwtService {

    // This should be handled better
    private final SecretKey secretKey = Jwts.SIG.HS256.key().build();
    private Claims claims;

    /* Returns the username which is available under Subject in payload.
    * */
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    /* Get specific claim from the JWT payload. As each claim of different
     * type we make this method generic
    * */

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        if(claims == null) {
            claims = getClaims(jwtToken);
        }

        return claimsResolver.apply(claims);
    }

    /* Get all the Claims or the body of the token
    * */
    public Claims getClaims(String jwtToken) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(jwtToken)
                .getPayload();
    }

   /*  Generate token for a user registering or signing for the first time
   * */

    public String generateToken(User user) {
        return generateToken(new HashMap<>(), user);
    }

    public String generateToken(Map<String, Object> extraClaims, User user) {
        return Jwts.builder()
                .claims().add(extraClaims).and()
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(getSigningKey())
                .compact();
    }

    private SecretKey getSigningKey() {
        return secretKey;
    }

    public boolean isValidToken(String jwtToken) {
        return extractExpiration(jwtToken).after(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }
}
