package org.owasp.appsensor.core;

import java.io.Serializable;

import javax.inject.Inject;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.google.common.net.InetAddresses;

/**
 * Identifier label for the system that detected the event. 
 * This will be either the client application, or possibly an external 
 * detection system, such as syslog, a WAF, network IDS, etc.  
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class DetectionSystem implements Serializable {

	private static final long serialVersionUID = -9213994652294519363L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	private String detectionSystemId;
	
	private IPAddress ipAddress;
	
	@Inject
	private transient IPAddress locator;

	public DetectionSystem() {}
	
	public DetectionSystem(String detectionSystemId) {
		setDetectionSystemId(detectionSystemId);
	}
	
	public DetectionSystem(String username, IPAddress ipAddress) {
		setDetectionSystemId(username);
		setIPAddress(ipAddress);
	}
	
	public String getDetectionSystemId() {
		return detectionSystemId;
	}

	public DetectionSystem setDetectionSystemId(String detectionSystemId) {
		this.detectionSystemId = detectionSystemId;
		
		// if IP is used as system id, setup IP address w/ geolocation
		if (InetAddresses.isInetAddress(detectionSystemId)) {
			this.ipAddress = locator.fromString(detectionSystemId);
		}
		
		return this;
	}

	public IPAddress getIPAddress() {
		return ipAddress;
	}

	public DetectionSystem setIPAddress(IPAddress ipAddress) {
		this.ipAddress = ipAddress;
		
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(detectionSystemId).
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
		
		DetectionSystem other = (DetectionSystem) obj;
		
		return new EqualsBuilder().
				append(detectionSystemId, other.getDetectionSystemId()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("detectionSystemId", detectionSystemId).
				append("ipAddress", ipAddress).
			    toString();
	}
	
}
