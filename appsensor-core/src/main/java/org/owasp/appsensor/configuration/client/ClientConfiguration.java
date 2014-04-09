package org.owasp.appsensor.configuration.client;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.configuration.ExtendedConfiguration;

/**
 * Represents the configuration for client-side components. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ClientConfiguration {

	/** Event manager for client-code to interact with appsensor */
	private String eventManagerImplementation;

	/** Extended configuration for event manager */
	private ExtendedConfiguration eventManagerExtendedConfiguration;
	
	/** Response handler */
	private String responseHandlerImplementation;
	
	/** Extended configuration for response handler */
	private ExtendedConfiguration responseHandlerExtendedConfiguration;
	
	/** User manager for performing responses on users */
	private String userManagerImplementation;
	
	/** Extended configuration for user manager */
	private ExtendedConfiguration userManagerExtendedConfiguration;
	
	/** Server connection with configuration info for rest/soap connections */
	private ServerConnection serverConnection;
	
	public String getEventManagerImplementation() {
		return eventManagerImplementation;
	}

	public ClientConfiguration setEventManagerImplementation(String eventManagerImplementation) {
		this.eventManagerImplementation = eventManagerImplementation;
		return this;
	}
	
	public ExtendedConfiguration getEventManagerExtendedConfiguration() {
		return eventManagerExtendedConfiguration;
	}

	public ClientConfiguration setEventManagerExtendedConfiguration(ExtendedConfiguration eventManagerExtendedConfiguration) {
		this.eventManagerExtendedConfiguration = eventManagerExtendedConfiguration;
		return this;
	}

	public String getResponseHandlerImplementation() {
		return responseHandlerImplementation;
	}

	public ClientConfiguration setResponseHandlerImplementation(String responseHandlerImplementation) {
		this.responseHandlerImplementation = responseHandlerImplementation;
		return this;
	}
	
	public ExtendedConfiguration getResponseHandlerExtendedConfiguration() {
		return responseHandlerExtendedConfiguration;
	}

	public ClientConfiguration setResponseHandlerExtendedConfiguration(ExtendedConfiguration responseHandlerExtendedConfiguration) {
		this.responseHandlerExtendedConfiguration = responseHandlerExtendedConfiguration;
		return this;
	}
	
	public String getUserManagerImplementation() {
		return userManagerImplementation;
	}

	public ClientConfiguration setUserManagerImplementation(String userManagerImplementation) {
		this.userManagerImplementation = userManagerImplementation;
		return this;
	}

	public ExtendedConfiguration getUserManagerExtendedConfiguration() {
		return userManagerExtendedConfiguration;
	}

	public ClientConfiguration setUserManagerExtendedConfiguration(ExtendedConfiguration userManagerExtendedConfiguration) {
		this.userManagerExtendedConfiguration = userManagerExtendedConfiguration;
		return this;
	}

	public ServerConnection getServerConnection() {
		return serverConnection;
	}

	public ClientConfiguration setServerConnection(ServerConnection serverConnection) {
		this.serverConnection = serverConnection;
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(eventManagerImplementation).
				append(responseHandlerImplementation).
				append(userManagerImplementation).
				append(serverConnection).
				toHashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		
		ClientConfiguration other = (ClientConfiguration) obj;
		
		return new EqualsBuilder().
				append(eventManagerImplementation, other.getEventManagerImplementation()).
				append(responseHandlerImplementation, other.getResponseHandlerImplementation()).
				append(userManagerImplementation, other.getUserManagerImplementation()).
				append(serverConnection, other.getServerConnection()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("eventManagerImplementation", eventManagerImplementation).
				append("responseHandlerImplementation", responseHandlerImplementation).
				append("userManagerImplementation", userManagerImplementation).
				append("serverConnection", serverConnection).
			    toString();
	}

}
