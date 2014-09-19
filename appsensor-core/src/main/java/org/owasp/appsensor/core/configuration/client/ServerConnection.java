package org.owasp.appsensor.core.configuration.client;

import javax.inject.Named;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.ClientApplication;

/**
 * Represents a connection to a server from a {@link ClientApplication}. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class ServerConnection {
	
	private static String DEFAULT_HEADER_NAME = "X-Appsensor-Client-Application-Name";
	
	/** type of server connection: rest/soap */
	private String type;
	
	/** The url to connect to  */
	private String url;
	
	/** The client application identifier header name, optionally overridden */
	private String clientApplicationIdentificationHeaderName;
	
	/** The client application identifier header value */
	private String clientApplicationIdentificationHeaderValue;
	
	public String getType() {
		return type;
	}
	
	public ServerConnection setType(String type) {
		this.type = type;
		return this;
	}
	
	public String getUrl() {
		return url;
	}

	public ServerConnection setUrl(String url) {
		this.url = url;
		
		return this;
	}
	
	public String getClientApplicationIdentificationHeaderName() {
		return clientApplicationIdentificationHeaderName;
	}
	
	public String getClientApplicationIdentificationHeaderNameOrDefault() {
		return (clientApplicationIdentificationHeaderName != null) ? clientApplicationIdentificationHeaderName : DEFAULT_HEADER_NAME;
	}

	public ServerConnection setClientApplicationIdentificationHeaderName(
			String clientApplicationIdentificationHeaderName) {
		this.clientApplicationIdentificationHeaderName = clientApplicationIdentificationHeaderName;
		
		return this;
	}

	public String getClientApplicationIdentificationHeaderValue() {
		return clientApplicationIdentificationHeaderValue;
	}
	
	public ServerConnection setClientApplicationIdentificationHeaderValue(
			String clientApplicationIdentificationHeaderValue) {
		this.clientApplicationIdentificationHeaderValue = clientApplicationIdentificationHeaderValue;
		
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(type).
				append(url).
				append(clientApplicationIdentificationHeaderName).
				append(clientApplicationIdentificationHeaderValue).
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
		
		ServerConnection other = (ServerConnection) obj;
		
		return new EqualsBuilder().
				append(type, other.getType()).
				append(url, other.getUrl()).
				append(clientApplicationIdentificationHeaderName, other.getClientApplicationIdentificationHeaderName()).
				append(clientApplicationIdentificationHeaderValue, other.getClientApplicationIdentificationHeaderValue()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("type", type).
				append("url", url).
				append("clientApplicationIdentificationHeaderName", clientApplicationIdentificationHeaderName).
			    append("clientApplicationIdentificationHeaderValue", clientApplicationIdentificationHeaderValue).
			    toString();
	}
	
}
