package org.owasp.appsensor.demo;

import java.util.ArrayList;
import java.util.List;

import org.owasp.appsensor.demo.filter.AuthFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

// if you use the @SpringBootApplication annotation, you have to put the 
// application class (this one) in the same namespace as what you want scanned, 
// ie. "org.owasp.appsensor" works fine since everything's there, but 
// "org.owasp.appsensor.demo" is not ok since none of the core classes will 
// get scanned and loaded. @SpringBootApplication is a wrapper annotation for 
// @Configuration, @EnableAutoConfiguration, and @ComponentScan. You can specify 
// a namespace value or values for @ComponentScan to get the appropriate 
// classes loaded

@Configuration
@EnableAutoConfiguration
@ComponentScan("org.owasp.appsensor")
public class DemoAppsensorExceptionManagerApplication {

    public static void main(String[] args) {
        @SuppressWarnings("unused")
		ApplicationContext ctx = SpringApplication.run(DemoAppsensorExceptionManagerApplication.class, args);
        System.err.println("----------");
        System.err.println("----------");
        System.err.println("----------");
        System.err.println("-BOOTED-");
        System.err.println("----------");
        System.err.println("----------");
        System.err.println("----------");
//        System.out.println("Let's inspect the beans provided by Spring Boot:");
//
//        String[] beanNames = ctx.getBeanDefinitionNames();
//        Arrays.sort(beanNames);
//        for (String beanName : beanNames) {
//            System.out.println("\t- " + beanName);
//        }
    }
	
	@Bean
	public javax.validation.Validator localValidatorFactoryBean() {
	   return new LocalValidatorFactoryBean();
	}
	
	@Bean
	public FilterRegistrationBean authFilter() {
		AuthFilter authFilter = new AuthFilter();
		FilterRegistrationBean filterRegBean = new FilterRegistrationBean();
	    filterRegBean.setFilter(authFilter);
	    List<String> urlPatterns = new ArrayList<String>();
	    urlPatterns.add("/*");
	    filterRegBean.setUrlPatterns(urlPatterns);
	    return filterRegBean;
	}
}
