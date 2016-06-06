package org.owasp.appsensor;

import org.owasp.appsensor.core.AppSensorClient;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;

// instead of @SpringBootApplication, using 3 separate annotations 
// so I can control exclusions for scanning - need to ignore the 
// client so it doesn't get loaded

@Configuration
@EnableAutoConfiguration
@ComponentScan(value="org.owasp.appsensor", excludeFilters = @ComponentScan.Filter(value = AppSensorClient.class, type = FilterType.ASSIGNABLE_TYPE))
public class AppsensorWsRestServerBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(AppsensorWsRestServerBootApplication.class, args);
    }
}
