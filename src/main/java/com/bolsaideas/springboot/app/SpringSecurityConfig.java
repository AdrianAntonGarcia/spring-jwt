package com.bolsaideas.springboot.app;
// JDBC

import com.bolsaideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsaideas.springboot.app.auth.filter.JWTAuthorizationFilter;

// import javax.sql.DataSource;

import com.bolsaideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsaideas.springboot.app.models.service.JpaUserDetailService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * EL @EnableGlobalMethodSecurity permite controlar mediante la anotación
 * Secured el acceso por role a las diferentes rutas en los propios mappings
 */
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private LoginSuccessHandler successHandler;

	// JDBC
	// @Autowired
	// private DataSource dataSource;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	JpaUserDetailService userDetailService;

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
		/**
		 * In memory authentication
		 */
		// PasswordEncoder encoder = passwordEncoder;
		// // UserBuilder users = User.builder().passwordEncoder(encoder::encode);
		// UserBuilder users = User.builder().passwordEncoder(password ->
		// encoder.encode(password));

		// builder.inMemoryAuthentication().withUser(users.username("admin").password("12345").roles("ADMIN",
		// "USER"))
		// .withUser(users.username("adrian").password("12345").roles("USER"));
		////////////////////////////

		/**
		 * Autenticación mediante jdbc
		 */
		// builder.jdbcAuthentication().dataSource(dataSource).passwordEncoder(passwordEncoder)
		// .usersByUsernameQuery("select username, password, enable from users where
		// username=?")
		// .authoritiesByUsernameQuery(
		// "select u.username, a.authority from authorities a inner join users u on
		// (a.user_id = u.id) where u.username=?");

		/**
		 * Con JPA
		 */
		builder.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		/**
		 * Reemplazamos lo comentado con anotaciones en los respectivos métodos
		 * En vez de trabajar con sesiones ahora vamos a trabajar con json web tokens
		 * Hay que deshabilitar el csrf .csrf().disable() y deshabilitamos el session
		 * security police con
		 * .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		 */
		http.authorizeRequests()
				.antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale")
				.permitAll()
				/* .antMatchers("/ver/**").hasAnyRole("USER") */
				/* .antMatchers("/uploads").hasAnyRole("USER") */
				/* .antMatchers("/form/**").hasAnyRole("ADMIN") */
				/* .antMatchers("/eliminar/**").hasAnyRole("ADMIN") */
				/* .antMatchers("/factura/**").hasAnyRole("ADMIN") */
				.anyRequest().authenticated()
				// .and().formLogin()
				// .successHandler(successHandler).loginPage("/login").permitAll().and().logout().permitAll().and()
				// .exceptionHandling().accessDeniedPage("/error_403")
				.and().addFilter(new JWTAuthenticationFilter(authenticationManager()))
				.addFilter(new JWTAuthorizationFilter(authenticationManager())).csrf().disable()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
}
