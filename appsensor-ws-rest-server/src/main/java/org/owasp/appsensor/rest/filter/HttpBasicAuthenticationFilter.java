package org.owasp.appsensor.rest.filter;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import org.glassfish.jersey.internal.util.Base64;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.ServerObjectFactory;

@Provider
public class HttpBasicAuthenticationFilter implements ContainerRequestFilter {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(HttpBasicAuthenticationFilter.class);
	
	private final static WebApplicationException unauthorized =
			   new WebApplicationException(
			       Response.status(Status.UNAUTHORIZED)
			               .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"realm\"")
			               .entity("Page requires login.").build());
	
//	public void filter(ContainerRequestContext context) {
//		String httpBasicHeaderEncoded = context.getHeaderString("Authorization");
//		
//		if (httpBasicHeaderEncoded != null) {
//			System.err.println("-- found http basic header of " + httpBasicHeaderEncoded);
//		} else {
//			System.err.println("-- no http basic header found");
//		}
//	}
	
	@Override
	public void filter(ContainerRequestContext context) 
	        throws WebApplicationException {

	    // Get the authentication passed in HTTP headers parameters
	    String encoded = context.getHeaderString("Authorization");
	    
	    if (encoded == null) {
	    	throw unauthorized;
	    }
	    
//			System.err.println("-- found http basic header of " + httpBasicHeaderEncoded);
//		} else {
//			System.err.println("-- no http basic header found");
//		}
	    
	    try {
	    	System.err.println("-- saw encoded as " + encoded);
	    	encoded = encoded.replaceFirst("[Bb]asic ", "");
		    String decoded = Base64.decodeAsString(encoded);
		    String[] decodedArray = decoded.split(":");
		    String username = decodedArray[0];
		    String password = decodedArray[1];
		    
		    System.err.println("-- found http basic u/p of " + username + " / " + password);
		    
	    } catch(Exception e) {
	    	logger.error("Exception thrown processing HTTP Basic request header.", e);
	    	
	    	throw unauthorized;
	    }

	}
}


