package org.owasp.appsensor.block.proxy;

import io.dropwizard.Application;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import java.util.EnumSet;

import javax.servlet.DispatcherType;
import javax.servlet.ServletRegistration;
import javax.ws.rs.client.Client;

import org.owasp.appsensor.block.proxy.domain.JerseyClientCache;
import org.owasp.appsensor.block.proxy.filter.BlockFilter;
import org.owasp.appsensor.block.proxy.servlet.ProxyServlet;
import org.owasp.appsensor.block.proxy.util.ConfigurationContext;

import de.spinscale.dropwizard.jobs.JobsBundle;

public class BlockProxyApplication extends Application<BlockProxyConfiguration> {

    public static void main(String[] args) throws Exception {
        new BlockProxyApplication().run(args);
    }

    @Override
    public String getName() {
        return "block-proxy";
    }

    @Override
    public void initialize(Bootstrap<BlockProxyConfiguration> bootstrap) {

        // Enable variable substitution with environment variables
        bootstrap.setConfigurationSourceProvider(new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(), new EnvironmentVariableSubstitutor(true)));

        // quartz scheduler
        bootstrap.addBundle(new JobsBundle("org.owasp.appsensor.block.proxy"));
    }

    @Override
    public void run(BlockProxyConfiguration configuration, Environment environment) {
    	
    	ConfigurationContext.set(configuration);
    	
        // block filter
        environment.servlets().addFilter("BlockFilter", new BlockFilter())
        	.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");
        
        ServletRegistration.Dynamic servlet = environment.servlets().addServlet("proxy", ProxyServlet.class);
        servlet.addMapping("/api/v1.0/blocks");
        servlet.setInitParameter("targetUri", configuration.getApplicationTargetUri());
        servlet.setInitParameter("log", "true");
        
        // jersey rest client config
        final Client client = new JerseyClientBuilder(environment)
                .using(environment)
        		.using(configuration.getJerseyClientConfiguration())
                .build("jersey-client");
        
        JerseyClientCache.setInstance(client);
    }
    
}