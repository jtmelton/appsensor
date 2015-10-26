package org.owasp.appsensor.rest.filter;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.handler.RestRequestHandler;

/**
 * This is the jax-rs container request filter that performs
 * authentication of the client applications. 
 * 
 * The authentication mechanism involves checking an HTTP request header 
 * for the username of the given client application. 
 * 
 * NOTE: This means that implementors must ensure that end users are not able 
 * to make direct requests to the service or it will be possible to masquerade 
 * as a valid client application. 
 * 
 * The intended deployment scenario is to use a standard reverse proxy setup 
 * whereby a web server or agent of some kind performs the authentication 
 * (SSO, HTTP Basic Auth, etc.) and then sets the request header key-value pair, 
 * and then forwards the request to the servlet container/app server where 
 * this container request filter then processes the request. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Provider
@Named
public class ClientApplicationIdentificationFilter implements ContainerRequestFilter {
	
	/** default name for client application identification header */
	private static String HEADER_NAME = "X-Appsensor-Client-Application-Name";
	
	private static boolean checkedConfigurationHeaderName = false;
	
	@Inject
	private AppSensorServer appSensorServer;
	
	@Override
	public void filter(ContainerRequestContext context) throws WebApplicationException {
		//should only run on first request
		if (! checkedConfigurationHeaderName) {
			updateHeaderFromConfiguration();
			checkedConfigurationHeaderName = true;
		}
		
	    // Get the client application identifier passed in HTTP headers parameters
	    String clientApplicationIdentifier = context.getHeaderString(HEADER_NAME);
	    
	    if (clientApplicationIdentifier == null) {
	    	throw new WebApplicationException(
				       Response.status(Status.UNAUTHORIZED)
		               .entity("Page requires sending configured client application identification header.").build());
	    }
	    
	    context.setProperty(RestRequestHandler.APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR, clientApplicationIdentifier);
	}
	
	private void updateHeaderFromConfiguration() {
		String configuredHeaderName = appSensorServer.getConfiguration().getClientApplicationIdentificationHeaderName();
		
		if (configuredHeaderName != null && configuredHeaderName.trim().length() > 0) {
			HEADER_NAME = configuredHeaderName;
		}
	}
}


