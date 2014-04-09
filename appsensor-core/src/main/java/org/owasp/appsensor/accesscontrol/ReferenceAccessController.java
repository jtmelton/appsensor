package org.owasp.appsensor.accesscontrol;

import javax.inject.Named;

import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This particular {@link AccessController} implementation simply checks the {@link ClientApplication}s 
 * role(s) to see if it matches the expected {@link Action}. If there is a match found, 
 * then the access is considered valid.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class ReferenceAccessController implements AccessController {
	
	/**
	 * {@inheritDoc}
	 */
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
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void assertAuthorized(ClientApplication clientApplication, Action action, Context context) throws NotAuthorizedException {
		if (! isAuthorized(clientApplication, action, context)) {
			throw new NotAuthorizedException("Access is not allowed for client application: " + clientApplication + 
					" when trying to perform action : " + action + 
					" using context: " + context);
		}
	}
}
