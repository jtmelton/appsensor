package org.owasp.appsensor;

import java.util.ArrayList;
import java.util.Collection;

import org.owasp.appsensor.accesscontrol.Role;

public class ClientApplication {
	
	private String name;
	
	private Collection<Role> roles = new ArrayList<Role>();

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Collection<Role> getRoles() {
		return roles;
	}

}
