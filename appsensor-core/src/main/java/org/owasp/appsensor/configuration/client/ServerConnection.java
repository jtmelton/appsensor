package org.owasp.appsensor.configuration.client;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * Represents a connection to a server from a client. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ServerConnection {
	
	/** type of server connection: rest/soap */
	private String type;
	
	/** The protocol that should be used: http or https */
	private String protocol;
	
	/** The host to connect to: IP or hostname */
	private String host;
	
	/** The port to connect to  */
	private int port;
	
	/** The path used: essentially the prefix where the webapp is deployed, eg. "/appsensor-ws-rest-server/api/v1" */
	private String path;
	
	public String getType() {
		return type;
	}
	
	public ServerConnection setType(String type) {
		this.type = type;
		return this;
	}
	
	public String getProtocol() {
		return protocol;
	}
	
	public ServerConnection setProtocol(String protocol) {
		this.protocol = protocol;
		return this;
	}
	
	public String getHost() {
		return host;
	}
	
	public ServerConnection setHost(String host) {
		this.host = host;
		return this;
	}
	
	public int getPort() {
		return port;
	}
	
	public ServerConnection setPort(int port) {
		this.port = port;
		return this;
	}
	
	public String getPath() {
		return path;
	}
	
	public ServerConnection setPath(String path) {
		this.path = path;
		return this;
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(type).
				append(protocol).
				append(host).
				append(port).
				append(path).
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
				append(protocol, other.getProtocol()).
				append(host, other.getHost()).
				append(port, other.getPort()).
				append(path, other.getPath()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("type", type).
				append("protocol", protocol).
				append("host", host).
				append("port", port).
				append("path", path).
			    toString();
	}
	
}
