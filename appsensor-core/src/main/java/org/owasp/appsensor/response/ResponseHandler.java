package org.owasp.appsensor.response;

import org.owasp.appsensor.Response;

/**
 * The ResponseHandler is executed when a {@link Response} needs to be executed. 
 * The ResponseHandler is used by the {@link org.owasp.appsensor.ClientApplication}, or possibly the server 
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
	/** disable a component for this specific user */
	public final static String DISABLE_COMPONENT_FOR_SPECIFIC_USER = "disableComponentForSpecificUser";
	/** disable a component for all users */
	public final static String DISABLE_COMPONENT_FOR_ALL_USERS = "disableComponentForAllUsers";
	
	/**
	 * The handle method is called when a given {@link org.owasp.appsensor.Response} should be processed. 
	 * It is the responsibility of the handle method to actually execute the intented {@link org.owasp.appsensor.Response}.
	 * 
	 * @param response {@link org.owasp.appsensor.Response} object that should be processed
	 */
	public void handle(Response response);
	
}
