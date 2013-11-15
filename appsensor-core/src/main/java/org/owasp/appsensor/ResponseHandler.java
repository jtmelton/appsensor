package org.owasp.appsensor;

public interface ResponseHandler {
	
	public final static String LOG = "log";
	public final static String LOGOUT = "logout"; 
	public final static String DISABLE_USER = "disableUser";
	public final static String DISABLE_COMPONENT_FOR_SPECIFIC_USER = "disableComponentForSpecificUser";
	public final static String DISABLE_COMPONENT_FOR_ALL_USERS = "disableComponentForAllUsers";
	
	public void handle(Response response);
	
}
