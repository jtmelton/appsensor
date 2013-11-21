package org.owasp.appsensor.configuration.client;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.eclipse.persistence.oxm.annotations.XmlPath;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "appsensor-client-config")
public class ClientConfiguration {

	@XmlPath("event-manager/@class")
	private String eventManagerImplementation;
	
	@XmlPath("response-handler/@class")
	private String responseHandlerImplementation;
	
	@XmlPath("user-manager/@class")
	private String userManagerImplementation;
	
	@XmlElement(name="server-connection")
	private ServerConnection serverConnection;
	
	public String getEventManagerImplementation() {
		return eventManagerImplementation;
	}

	public ClientConfiguration setEventManagerImplementation(String eventManagerImplementation) {
		this.eventManagerImplementation = eventManagerImplementation;
		return this;
	}
	
	public String getResponseHandlerImplementation() {
		return responseHandlerImplementation;
	}

	public ClientConfiguration setResponseHandlerImplementation(String responseHandlerImplementation) {
		this.responseHandlerImplementation = responseHandlerImplementation;
		return this;
	}
	
	public String getUserManagerImplementation() {
		return userManagerImplementation;
	}

	public ClientConfiguration setUserManagerImplementation(String userManagerImplementation) {
		this.userManagerImplementation = userManagerImplementation;
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
