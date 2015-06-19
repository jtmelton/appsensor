package org.owasp.appsensor;

import org.owasp.appsensor.core.AppSensorServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;


//instead of @SpringBootApplication, using 3 separate annotations 
//so I can control exclusions for scanning - need to ignore the 
//client so it doesn't get loaded

@Configuration
@EnableAutoConfiguration
@ComponentScan(value="org.owasp.appsensor", excludeFilters = @ComponentScan.Filter(value = AppSensorServer.class, type = FilterType.ASSIGNABLE_TYPE))
public class AppsensorWsRestClientBootDataGeneratorApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(AppsensorWsRestClientBootDataGeneratorApplication.class, args);
        
        DataGenerator generator = context.getBean(DataGenerator.class);
        
        generator.execute();
    }
    
}
