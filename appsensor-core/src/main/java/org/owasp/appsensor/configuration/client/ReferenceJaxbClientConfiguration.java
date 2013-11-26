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
public class ReferenceJaxbClientConfiguration implements ClientConfiguration {

	@XmlPath("event-manager/@class")
	private String eventManagerImplementation;

	@XmlPath("response-handler/@class")
	private String responseHandlerImplementation;
	
	@XmlPath("user-manager/@class")
	private String userManagerImplementation;
	
	@XmlElement(name="server-connection")
	private ReferenceJaxbServerConnection serverConnection;
	
	@Override
	public String getEventManagerImplementation() {
		return eventManagerImplementation;
	}

	@Override
	public ReferenceJaxbClientConfiguration setEventManagerImplementation(String eventManagerImplementation) {
		this.eventManagerImplementation = eventManagerImplementation;
		return this;
	}
	
	@Override
	public String getResponseHandlerImplementation() {
		return responseHandlerImplementation;
	}

	@Override
	public ReferenceJaxbClientConfiguration setResponseHandlerImplementation(String responseHandlerImplementation) {
		this.responseHandlerImplementation = responseHandlerImplementation;
		return this;
	}
	
	@Override
	public String getUserManagerImplementation() {
		return userManagerImplementation;
	}

	@Override
	public ReferenceJaxbClientConfiguration setUserManagerImplementation(String userManagerImplementation) {
		this.userManagerImplementation = userManagerImplementation;
		return this;
	}

	@Override
	public ServerConnection getServerConnection() {
		return serverConnection;
	}

	@Override
	public ReferenceJaxbClientConfiguration setServerConnection(ServerConnection serverConnection) {
		if(serverConnection instanceof ReferenceJaxbServerConnection) {
			this.serverConnection = (ReferenceJaxbServerConnection)serverConnection;
		}
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
		
		ReferenceJaxbClientConfiguration other = (ReferenceJaxbClientConfiguration) obj;
		
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
