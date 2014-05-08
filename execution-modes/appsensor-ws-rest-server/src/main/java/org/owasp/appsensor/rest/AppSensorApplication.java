package org.owasp.appsensor.rest;

import javax.inject.Named;

import org.glassfish.jersey.server.ResourceConfig;

/**
 * This Jersey class provides the runtime with the classes that need to
 * be managed, allowing {@link javax.ws.rs.core.Context} injections 
 * to be made on the exposed classes. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class AppSensorApplication extends ResourceConfig {
	
	public AppSensorApplication() {
        packages(true, "org.owasp.appsensor");
    }

}
