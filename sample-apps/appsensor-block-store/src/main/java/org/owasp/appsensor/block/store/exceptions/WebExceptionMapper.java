package org.owasp.appsensor.block.store.exceptions;

import java.util.HashMap;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

// pulled from http://nbsoftsolutions.com/blog/writing-a-dropwizard-json-app
public class WebExceptionMapper implements ExceptionMapper<WebApplicationException> {
	
    @SuppressWarnings("serial")
	@Override
    public Response toResponse(final WebApplicationException e) {
    	
        // If the message did not come with a status, we'll default to an internal
        // server error status.
        int status = e.getResponse() == null ? 500 : e.getResponse().getStatus();

        // Get a nice human readable message for our status code if the exception
        // doesn't already have a message
        final String msg = e.getMessage() == null ?
                "Unknown Error Occurred" : e.getMessage();

        // Create a JSON response with the provided hashmap
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(new HashMap<String, String>() { {
                    put("error", msg);
                } }).build();
    }
    
}