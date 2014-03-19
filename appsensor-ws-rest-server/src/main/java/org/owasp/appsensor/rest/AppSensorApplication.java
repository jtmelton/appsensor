package org.owasp.appsensor.rest;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.owasp.appsensor.handler.RestRequestHandler;
import org.owasp.appsensor.reporting.RestReportingEngine;
import org.owasp.appsensor.rest.filter.ClientApplicationIdentificationFilter;

/**
 * This JAX-RS class provides the runtime with the classes that need to
 * be managed, allowing {@link javax.ws.rs.core.Context} injections 
 * to be made on the exposed classes.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class AppSensorApplication extends Application {
	
	/**
	 * Add classes that need to have DI to Application
	 */
	@Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> restClasses = new HashSet<Class<?>>();
        restClasses.add(RestRequestHandler.class);
        restClasses.add(ClientApplicationIdentificationFilter.class);
        restClasses.add(RestReportingEngine.class);
        return restClasses;
    }
    
}
