package org.owasp.appsensor.configuration.client;

public interface ClientConfiguration {

	public String getEventManagerImplementation();

	public ClientConfiguration setEventManagerImplementation(String eventManagerImplementation);
	
	public String getResponseHandlerImplementation();

	public ClientConfiguration setResponseHandlerImplementation(String responseHandlerImplementation);
	
	public String getUserManagerImplementation();

	public ClientConfiguration setUserManagerImplementation(String userManagerImplementation);

	public ServerConnection getServerConnection();

	public ClientConfiguration setServerConnection(ServerConnection serverConnection);

}
