package org.owasp.appsensor.accesscontrol;

import org.owasp.appsensor.ClientApplication;

/**
 * This interface is meant to gate access to the different actions 
 * that can be performed to ensure a client has appropriate permissions.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface AccessController {

	public boolean isAuthorized(ClientApplication clientApplication, Action action, Context context);
	
}
