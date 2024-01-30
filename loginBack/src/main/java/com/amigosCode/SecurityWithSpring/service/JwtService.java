package com.amigosCode.SecurityWithSpring.service;
import com.amigosCode.SecurityWithSpring.user.AppUserRoles;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@NoArgsConstructor
public class JwtService {


    private static final String SECRET_KEY = "6623304a1ccf0ae6e7b8c5f988e0a3985f8523e72bc302724bfbce9af81cbac6";


    public String extractUsername(String token) {
        return extractClaim(token , Claims::getSubject);
    }



    public <T> T extractClaim(String token , Function<Claims , T > claimsResolver){
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    //! GENERACION DE TOKENS
    public String generateToken(UserDetails userDetails , String firstname , String lastname , String email , AppUserRoles role){
        return generateToken(new HashMap<>() , userDetails  , firstname , lastname , email , role);
    }

    public String generateToken(
            Map<String , Object> extraClaims ,
            UserDetails userDetails,
            String firstname,
            String lastname,
            String email,
            AppUserRoles role
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .claim("firstname"  , firstname)
                .claim("lastname"  , lastname)
                .claim("email"  , email)
                .claim("role"  , role)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 ))
                .signWith(getSignInKey() , SignatureAlgorithm.HS256)
                .compact();
    }

    //! VALIDACION DE TOKENS
    public boolean isTokenValid(String token , UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token , Claims::getExpiration);
    }


    //! CLAVE DE VALIDACION
    public Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
