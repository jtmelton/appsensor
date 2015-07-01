package org.owasp.appsensor;

import org.owasp.appsensor.core.AppSensorClient;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.web.socket.server.standard.ServerEndpointExporter;

// instead of @SpringBootApplication, using 3 separate annotations 
// so I can control exclusions for scanning - need to ignore the 
// client so it doesn't get loaded

@Configuration
@EnableAutoConfiguration
@ComponentScan(value="org.owasp.appsensor", excludeFilters = @ComponentScan.Filter(value = AppSensorClient.class, type = FilterType.ASSIGNABLE_TYPE))
public class AppsensorWsRestServerWithWebsocketBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(AppsensorWsRestServerWithWebsocketBootApplication.class, args);
    }
    
    @Bean
    public ServerEndpointExporter serverEndpointExporter() {
        return new ServerEndpointExporter();
    }
    
}

//package org.owasp.appsensor.jersey;
//
//import org.glassfish.jersey.server.ResourceConfig;
//import org.glassfish.jersey.server.ServerProperties;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//
//@Configuration
//@Primary
//public class JerseyConfig extends ResourceConfig {
//	
//	public JerseyConfig() {
//		packages(true, "org.owasp.appsensor");
//		property(ServerProperties.BV_SEND_ERROR_IN_RESPONSE, true);
//        property(ServerProperties.JSON_PROCESSING_FEATURE_DISABLE, false);
//        property(ServerProperties.MOXY_JSON_FEATURE_DISABLE, true);
//        property(ServerProperties.WADL_FEATURE_DISABLE, true);
//	}
//	
//}

