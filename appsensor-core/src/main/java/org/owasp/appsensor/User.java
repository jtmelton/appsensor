package org.owasp.appsensor;

import java.io.Serializable;

/**
 * The standard User object. The base implementation assumes the username is 
 * provided by the client application. It is up to the client application to 
 * manage the username. If the username doesn't exist, the base implementation 
 * will attempt to fall back to the IP address as an identifier.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class User implements Serializable {

	private static final long serialVersionUID = 5084152023446797592L;

	private String username;

	private String ipAddress;
	
	public User() {}
	
	public User(String username, String ipAddress) {
		setUsername(username);
		setIpAddress(ipAddress);
		
		//attempt fallback to IP address
		if (username == null) {
			setUsername(ipAddress);
		}
	}
	
	public String getUsername() {
		return username;
	}

	public User setUsername(String username) {
		this.username = username;
		
		//attempt fallback to IP address
		if (username == null) {
			setUsername(ipAddress);
		}
				
		return this;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public User setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
		return this;
	}
	
}
