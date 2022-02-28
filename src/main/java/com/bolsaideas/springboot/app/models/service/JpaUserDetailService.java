package com.bolsaideas.springboot.app.models.service;

import java.util.ArrayList;
import java.util.List;

import com.bolsaideas.springboot.app.models.dao.IUsuarioDao;
import com.bolsaideas.springboot.app.models.entity.Role;
import com.bolsaideas.springboot.app.models.entity.Usuario;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("jpaUserDetailService")
public class JpaUserDetailService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(JpaUserDetailService.class);

    @Autowired
    private IUsuarioDao usuarioDao;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioDao.findByUsername(username);
        if (usuario == null) {
            logger.error("Error login: No existe el usuario " + username + " en la base de datos");
            throw new UsernameNotFoundException("Usuario no existe: " + username);
        }
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (Role role : usuario.getRoles()) {
            logger.info("Role".concat(role.getAuthority()));
            authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
        }
        if (authorities.isEmpty()) {
            logger.error("Error login: usuario " + username + " no tiene roles asignados!");
            throw new UsernameNotFoundException("No tiene roles asignados!: " + username);
        }
        return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true,
                authorities);
    }

}
