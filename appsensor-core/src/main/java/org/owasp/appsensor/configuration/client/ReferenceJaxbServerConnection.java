package org.owasp.appsensor.configuration.client;

import javax.xml.bind.annotation.XmlElement;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.eclipse.persistence.oxm.annotations.XmlPath;

public class ReferenceJaxbServerConnection implements ServerConnection {
	
	@XmlPath("@type")
	private String type;
	
	@XmlElement(name="server-connection-config/protocol")
	private String protocol;
	@XmlElement(name="server-connection-config/host")
	private String host;
	@XmlElement(name="server-connection-config/port")
	private int port;
	@XmlElement(name="server-connection-config/path")
	private String path;
	
	@Override
	public String getType() {
		return type;
	}
	
	@Override
	public ReferenceJaxbServerConnection setType(String type) {
		this.type = type;
		return this;
	}
	
	@Override
	public String getProtocol() {
		return protocol;
	}
	
	@Override
	public ReferenceJaxbServerConnection setProtocol(String protocol) {
		this.protocol = protocol;
		return this;
	}
	
	@Override
	public String getHost() {
		return host;
	}
	
	@Override
	public ReferenceJaxbServerConnection setHost(String host) {
		this.host = host;
		return this;
	}
	
	@Override
	public int getPort() {
		return port;
	}
	
	@Override
	public ReferenceJaxbServerConnection setPort(int port) {
		this.port = port;
		return this;
	}
	
	@Override
	public String getPath() {
		return path;
	}
	
	@Override
	public ReferenceJaxbServerConnection setPath(String path) {
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
		
		ReferenceJaxbServerConnection other = (ReferenceJaxbServerConnection) obj;
		
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
