package org.owasp.appsensor;

import java.util.ArrayList;
import java.util.Collection;

import org.owasp.appsensor.accesscontrol.Role;

/**
 * The ClientApplication object represents a consumer of the AppSensor 
 * services in any of the client-server style setups.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ClientApplication {
	
	/** The name of the client application */
	private String name;
	
	/** The collection of {@link Role}s associated with this client application */
	private Collection<Role> roles;

	public String getName() {
		return name;
	}

	public ClientApplication setName(String name) {
		this.name = name;
		return this;
	}

	public Collection<Role> getRoles() {
		return roles;
	}

	public void setRoles(Collection<Role> roles) {
		this.roles = roles;
	}
}
