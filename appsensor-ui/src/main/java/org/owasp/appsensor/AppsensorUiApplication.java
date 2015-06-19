package org.owasp.appsensor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;

@SpringBootApplication
public class AppsensorUiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AppsensorUiApplication.class, args);
    }
    
    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer(){
        return new AppSensorErrorCustomizer();
    }

    private static class AppSensorErrorCustomizer implements EmbeddedServletContainerCustomizer {

        @Override
        public void customize(ConfigurableEmbeddedServletContainer container) {
        	ErrorPage error400Page = new ErrorPage(HttpStatus.BAD_REQUEST, "/400.html");
            ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED, "/401.html");
            ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND, "/404.html");
            ErrorPage error500Page = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/500.html");
 
            container.addErrorPages(error400Page, error401Page, error404Page, error500Page);
        }
    }
    
}
