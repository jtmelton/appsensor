package org.owasp.appsensor.block.store;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import org.owasp.appsensor.block.store.exceptions.WebExceptionMapper;
import org.owasp.appsensor.block.store.resources.BlockResource;
import org.owasp.appsensor.block.store.service.BlockList;
import org.owasp.appsensor.block.store.service.BlockListFactory;

import de.spinscale.dropwizard.jobs.JobsBundle;

public class BlockStoreApplication extends Application<BlockStoreConfiguration> {

    public static void main(String[] args) throws Exception {
        new BlockStoreApplication().run(args);
    }

    @Override
    public String getName() {
        return "block-store";
    }

    @Override
    public void initialize(Bootstrap<BlockStoreConfiguration> bootstrap) {

        // Enable variable substitution with environment variables
        bootstrap.setConfigurationSourceProvider(new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(), new EnvironmentVariableSubstitutor(true)));

        // quartz scheduler
        bootstrap.addBundle(new JobsBundle("org.owasp.appsensor.block.store"));
    }

    @Override
    public void run(BlockStoreConfiguration configuration, Environment environment) {
    	
        // services
    	final BlockList blockList = BlockListFactory.getInstance();
    	
        // resources
        environment.jersey().register( new BlockResource(blockList) );
        
        // exception mappers
        // check these urls if this becomes an issue
        // http://thoughtspark.org/2013/02/25/dropwizard-and-jersey-exceptionmappers/
        // http://nbsoftsolutions.com/blog/writing-a-dropwizard-json-app
        environment.jersey().register(new WebExceptionMapper());
        
    }
    
}