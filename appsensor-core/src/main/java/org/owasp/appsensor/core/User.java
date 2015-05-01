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
 * The standard User object. This represents the end user in the system, 
 * NOT the client application. 
 * 
 * The base implementation assumes the username is provided by the client application. 
 * 
 * It is up to the client application to manage the username. 
 * The username could be anything, an actual username, an IP address, 
 * or any other identifier desired. The core notion is that any desired 
 * correlation on the user is done by comparing the username.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class User implements Serializable {

	private static final long serialVersionUID = 5084152023446797592L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	private String username;
	
	private IPAddress ipAddress;
	
	@Inject
	private transient IPAddress locator;

	public User() {}
	
	public User(String username) {
		setUsername(username);
	}
	
	public User(String username, IPAddress ipAddress) {
		//set ip first so the setUsername call to geolocate won't run if it's already explicitly set
		setIPAddress(ipAddress);
		setUsername(username);
	}
	
	public String getUsername() {
		return username;
	}

	public User setUsername(String username) {
		this.username = username;
		
		// if IP is used as username, setup IP address w/ geolocation
		if (ipAddress != null && InetAddresses.isInetAddress(username)) {
			this.ipAddress = locator.fromString(username);
		}
		
		return this;
	}
	
	public IPAddress getIPAddress() {
		return ipAddress;
	}

	public User setIPAddress(IPAddress ipAddress) {
		this.ipAddress = ipAddress;
		
		return this;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(username).
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
		
		User other = (User) obj;
		
		return new EqualsBuilder().
				append(username, other.getUsername()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("username", username).
				append("ipAddress", ipAddress).
			    toString();
	}
	
}
