package com.bolsaideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.bolsaideas.springboot.app.auth.service.JWTService;
import com.bolsaideas.springboot.app.auth.service.JWTServiceImpl;
import com.bolsaideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Filtro que está pendiente de la ruta del login para autenticar al usuario y
 * generale un token
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private JWTService jwtService;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
        this.jwtService = jwtService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        /**
         * Obteniendo los parametros por request params
         */
        String username = obtainUsername(request);
        username = (username != null) ? username : "";

        String password = obtainPassword(request);
        password = (password != null) ? password : "";

        if (username != "" && password != "") {
            logger.info("Username desde request parameter (form-data): " + username);
            logger.info("Password desde request parameter (form-data): " + password);
        } else {
            /**
             * Si no vienen por query params los sacamos del body raw
             * Convertimos Json a objeto
             */
            System.out.println("entro");
            Usuario user = null;
            try {
                user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
                username = user.getUsername();
                password = user.getPassword();
                logger.info("Username desde request InputStream (raw): " + username);
                logger.info("Password desde request InputStream (raw): " + password);
            } catch (IOException e) {

                e.printStackTrace();
            }
        }
        username = username.trim();

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authToken);
    }

    /**
     * Cuándo la autenticación ha ido de manera correcta
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        String token = jwtService.create(authResult);
        response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);
        Map<String, Object> body = new HashMap<String, Object>();
        body.put("token", token);
        body.put("user", authResult.getName());
        body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", authResult.getName()));
        // Convertimos a json
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        Map<String, Object> body = new HashMap<String, Object>();
        body.put("mensaje", "Error de autenticación: username o password incorrecto!");
        body.put("error", failed.getMessage());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401);
        response.setContentType("application/json");

    }

}
