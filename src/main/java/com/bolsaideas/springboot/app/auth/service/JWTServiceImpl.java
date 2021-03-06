package com.bolsaideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.SecretKey;

import com.bolsaideas.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTServiceImpl implements JWTService {

    public static final SecretKey keyJwt = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // 4 horas
    public static final long EXPIRATION_DATE = 14000000L;

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final String HEADER_STRING = "Authorization";

    @Override
    public String create(Authentication auth) throws IOException {
        User user = ((User) auth.getPrincipal());
        // String token = Jwts.builder().setSubject(authResult.getName()).;
        // La clave secreta se genera de forma automática

        Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
        Claims claims = Jwts.claims();
        // Colocamos los roles como json

        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        // JWT token
        // keyJwt = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .signWith(keyJwt)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
                .compact();
        return token;
    }

    @Override
    public boolean validate(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public Claims getClaims(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(keyJwt).build()
                .parseClaimsJws(resolve(token)).getBody();
        return claims;
    }

    @Override
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    @Override
    public Collection<? extends GrantedAuthority> getRoles(String token)
            throws StreamReadException, DatabindException, IOException {
        Object roles = getClaims(token).get("authorities");
        System.out.println(roles);
        Collection<? extends GrantedAuthority> authorities = Arrays
                .asList(new ObjectMapper().addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                        .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
        return authorities;
    }

    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith(TOKEN_PREFIX)) {
            return token.replace(TOKEN_PREFIX, "");
        } else {
            return null;
        }
    }

}
