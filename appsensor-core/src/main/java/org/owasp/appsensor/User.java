package org.owasp.appsensor;

import java.io.Serializable;

public class User implements Serializable {

	private static final long serialVersionUID = 5084152023446797592L;

	private String username;

	private String ipAddress;
	
	public User() {}
	
	public User(String username, String ipAddress) {
		setUsername(username);
		setIpAddress(ipAddress);
	}
	
	public String getUsername() {
		return username;
	}

	public User setUsername(String username) {
		this.username = username;
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
