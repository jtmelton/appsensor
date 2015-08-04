package org.owasp.appsensor;

import java.util.concurrent.TimeUnit;

import org.owasp.appsensor.configuration.stax.client.StaxClientConfiguration;
import org.owasp.appsensor.configuration.stax.server.StaxServerConfiguration;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.reporting.WebSocketReportingEngine;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.ErrorPage;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.google.common.cache.CacheBuilder;

//instead of @SpringBootApplication, using 3 separate annotations 
//so I can control exclusions for scanning - need to ignore the 
//client so it doesn't get loaded

@Configuration
@EnableAutoConfiguration
@ComponentScan(value="org.owasp.appsensor", excludeFilters = {
			@ComponentScan.Filter(value = AppSensorClient.class, type = FilterType.ASSIGNABLE_TYPE), 
			@ComponentScan.Filter(value = AppSensorServer.class, type = FilterType.ASSIGNABLE_TYPE),
			@ComponentScan.Filter(value = StaxClientConfiguration.class, type = FilterType.ASSIGNABLE_TYPE),
			@ComponentScan.Filter(value = StaxServerConfiguration.class, type = FilterType.ASSIGNABLE_TYPE),
			@ComponentScan.Filter(value = WebSocketReportingEngine.class, type = FilterType.ASSIGNABLE_TYPE)
		}
)
@EnableScheduling
@EnableCaching
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
    
    @Bean
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager() {

            @Override
            protected Cache createConcurrentMapCache(final String name) {
                return new ConcurrentMapCache(name,
                    CacheBuilder.newBuilder().expireAfterWrite(30, TimeUnit.SECONDS).maximumSize(100).build().asMap(), false);
            }
        };

        return cacheManager;
    	
    }
    
}
