package org.owasp.appsensor.ui.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebMvcSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired 
	private AuthenticationSuccessHandler successHandler;

	private static final String AUTHORITIES_BY_USERNAME_QUERY = 
			"select u.username,a.authority "
				+ "from users u, "
				+ "authorities a, "
				+ "user_authorities ua "
			+ "where u.username = ua.username "
				+ "and ua.authority_id = a.id "
				+ "and u.username = ?";
	
	private static final String USERS_BY_USERNAME_QUERY = "select username,password,enabled from users where username = ?"; 
			
	private static final String GROUP_AUTHORITIES_BY_USERNAME_QUERY = 
			"select g.id, g.group_name, a.authority "
			+ "from users u, "
				+ "authorities a, "
				+ "`groups` g, "
				+ "group_authorities ga, "
				+ "group_users gu "
			+ "where u.username = gu.username "
				+ "and gu.group_id = g.id "
				+ "and g.id = ga.group_id "
				+ "and ga.authority_id = a.id "
				+ "and u.username = ?";
	
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//        	.headers()
//		        .contentTypeOptions()
//		        .xssProtection()
//		        .cacheControl()
//		        .httpStrictTransportSecurity()
//		        .frameOptions()
//		        .addHeaderWriter(new StaticHeadersWriter("Content-Security-Policy","default-src 'self'; style-src 'self'; img-src 'self'"))
//		        .addHeaderWriter(new StaticHeadersWriter("X-Content-Security-Policy","default-src 'self'; style-src 'self'; img-src 'self'"))
//		        .addHeaderWriter(new StaticHeadersWriter("X-WebKit-CSP","default-src 'self'; style-src 'self'; img-src 'self'"))
//		        .and()
            .authorizeRequests()
            	.antMatchers("/webjars/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .successHandler(successHandler)
                .permitAll()
                .and()
            .logout()
            	.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            	.logoutSuccessUrl("/login")
            	.invalidateHttpSession(true)
                .permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	auth
		.jdbcAuthentication()
			.dataSource(dataSource)
			.authoritiesByUsernameQuery(AUTHORITIES_BY_USERNAME_QUERY)
			.usersByUsernameQuery(USERS_BY_USERNAME_QUERY)
			.groupAuthoritiesByUsername(GROUP_AUTHORITIES_BY_USERNAME_QUERY)
			.passwordEncoder(new BCryptPasswordEncoder(12));
		
    	JdbcUserDetailsManager manager = auth
    		.jdbcAuthentication()
    		.getUserDetailsService();
    	
    	// allow both user specific roles and roles picked up by a group the user is in
    	manager.setEnableAuthorities(true);
    	manager.setEnableGroups(true);
    }
    
}
