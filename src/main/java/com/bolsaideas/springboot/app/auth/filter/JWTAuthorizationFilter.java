package com.bolsaideas.springboot.app.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.bolsaideas.springboot.app.auth.service.JWTService;
import com.bolsaideas.springboot.app.auth.service.JWTServiceImpl;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private JWTService jwtService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;

    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
        if (!requiredAuthentication(header)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = null;
        if (jwtService.validate(header)) {
            System.out.println("Validado");
            authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null,
                    jwtService.getRoles(header));
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    protected boolean requiredAuthentication(String header) {
        if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
            return false;
        } else {
            return true;
        }
    }

}
