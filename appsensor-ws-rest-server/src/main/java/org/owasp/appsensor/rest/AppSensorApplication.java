package org.owasp.appsensor.rest;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.owasp.appsensor.handler.RestRequestHandler;
import org.owasp.appsensor.rest.filter.ClientApplicationIdentificationFilter;

public class AppSensorApplication extends Application {
	
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> restClasses = new HashSet<Class<?>>();
        restClasses.add(RestRequestHandler.class);
        restClasses.add(ClientApplicationIdentificationFilter.class);
        return restClasses;
    }
    
}
