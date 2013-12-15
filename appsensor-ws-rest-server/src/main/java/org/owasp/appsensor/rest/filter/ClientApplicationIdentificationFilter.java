package org.owasp.appsensor.rest.filter;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import org.owasp.appsensor.ServerObjectFactory;

@Provider
public class ClientApplicationIdentificationFilter implements ContainerRequestFilter {
	
	private final static WebApplicationException unauthorized =
			   new WebApplicationException(
			       Response.status(Status.UNAUTHORIZED)
			               .entity("Page requires sending configured client application identification header.").build());
	
	/** default name for client application identification header */
	private static String HEADER_NAME = "X-Appsensor-Client-Application-Name";
	
	static {
		String configuredHeaderName = ServerObjectFactory.getConfiguration().getClientApplicationIdentificationHeaderName();
		
		if (configuredHeaderName != null && configuredHeaderName.trim().length() > 0) {
			HEADER_NAME = configuredHeaderName;
		}
	}
	
	@Override
	public void filter(ContainerRequestContext context) 
	        throws WebApplicationException {

	    // Get the client application identifier passed in HTTP headers parameters
	    String clientApplicationIdentifier = context.getHeaderString(HEADER_NAME);
	    
	    if (clientApplicationIdentifier == null) {
	    	throw unauthorized;
	    }
	}
}


