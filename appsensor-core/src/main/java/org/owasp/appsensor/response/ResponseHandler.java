package org.owasp.appsensor.response;

import org.owasp.appsensor.Response;

/**
 * The ResponseHandler is executed when a {@link Response} needs to be executed. 
 * The ResponseHandler is used by the client application, or possibly the server 
 * side in a local configuration.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface ResponseHandler {
	
	/** provide increased logging for this specific user */
	public final static String LOG = "log";
	/** logout this specific user */
	public final static String LOGOUT = "logout"; 
	/** disable this specific user */
	public final static String DISABLE_USER = "disableUser";
	public final static String DISABLE_COMPONENT_FOR_SPECIFIC_USER = "disableComponentForSpecificUser";
	public final static String DISABLE_COMPONENT_FOR_ALL_USERS = "disableComponentForAllUsers";
	
	/**
	 * The handle method is called when a given response should be processed. 
	 * It is the responsibility of the handle method to actually execute the intented response.
	 * 
	 * @param response Response object that should be processed
	 */
	public void handle(Response response);
	
}
