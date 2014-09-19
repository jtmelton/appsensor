package org.owasp.appsensor.core.accesscontrol;

import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;

/**
 * This interface is meant to gate access to the different {@link Action} 
 * that can be performed to ensure a {@link ClientApplication} has appropriate permissions.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface AccessController {

	public boolean isAuthorized(ClientApplication clientApplication, Action action, Context context);
	
	public void assertAuthorized(ClientApplication clientApplication, Action action, Context context) throws NotAuthorizedException;
	
}
