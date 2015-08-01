package org.owasp.appsensor.ui.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebMvcSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
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
                .defaultSuccessUrl("/", false)
                .permitAll()
                .and()
            .logout()
            	.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            	.logoutSuccessUrl("/login")
            	.invalidateHttpSession(true)
                .permitAll();
//        	.headers()
//		        .addHeaderWriter(new StaticHeaderWriter("X-Content-Security-Policy","default-src 'self'"))
//		        .addHeaderWriter(new StaticHeaderWriter("X-WebKit-CSP","default-src 'self'"));
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
    
}
