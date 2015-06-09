package org.owasp.appsensor;

import org.owasp.appsensor.demo.InMemoryNoteRepository;
import org.owasp.appsensor.demo.Note;
import org.owasp.appsensor.demo.NoteRepository;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

@SpringBootApplication
public class DemoAppsensorLocalApplication {

    public static void main(String[] args) {
    	@SuppressWarnings("unused")
		ApplicationContext ctx = SpringApplication.run(DemoAppsensorLocalApplication.class, args);
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
	public NoteRepository noteRepository() {
		return new InMemoryNoteRepository();
	}

	@Bean
	public Converter<String, Note> messageConverter() {
		return new Converter<String, Note>() {
			@Override
			public Note convert(String id) {
				return noteRepository().findNote(Long.valueOf(id));
			}
		};
	}
	
	@Bean
	public javax.validation.Validator localValidatorFactoryBean() {
	   return new LocalValidatorFactoryBean();
	}
	
//	@Override
//	public void addResourceHandlers(ResourceHandlerRegistry registry) {
//		if (!registry.hasMappingForPattern("/webjars/**")) {
//			registry.addResourceHandler("/webjars/**").addResourceLocations(
//					"classpath:/META-INF/resources/webjars/");
//		}
//		if (!registry.hasMappingForPattern("/**")) {
//			registry.addResourceHandler("/**").addResourceLocations(
//					RESOURCE_LOCATIONS);
//		}
//	}
	
}
