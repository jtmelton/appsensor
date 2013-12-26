package org.owasp.appsensor;

import java.io.Serializable;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The standard User object. The base implementation assumes the username is 
 * provided by the client application. 
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
public class User implements Serializable {

	private static final long serialVersionUID = 5084152023446797592L;

	private String username;

	public User() {}
	
	public User(String username) {
		setUsername(username);
	}
	
	public String getUsername() {
		return username;
	}

	public User setUsername(String username) {
		this.username = username;
		
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
			    toString();
	}
	
}
