package org.owasp.appsensor.accesscontrol;

import org.owasp.appsensor.ClientApplication;

public class ReferenceAccessController implements AccessController {
	
	@Override
	public boolean isAuthorized(ClientApplication clientApplication, Action action, Context context) {
		boolean authorized = false;

		if (clientApplication != null && action != null && action.toString() != null && action.toString().trim().length() > 0) {
			for (Role role : clientApplication.getRoles()) {
				
				//simple check to make sure that 
				//the value of the action matches the value of one of the roles (exact match)
				if (role != null && role.toString() != null && 
						role.toString().equals(action.toString())) {
					authorized = true; 
					break;
				}
			}
		}
		
		return authorized;
	}
}
