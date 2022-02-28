package com.bolsaideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

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

@Service
public class JWTServiceImpl implements JWTService {

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
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .signWith(keyJwt)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000L * 4L))
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
        Object roles = getClaims(token);
        Collection<? extends GrantedAuthority> authorities = Arrays
                .asList(new ObjectMapper()
                        .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                        .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
        return authorities;
    }

    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.replace("Bearer ", "");
        } else {
            return null;
        }
    }

}
