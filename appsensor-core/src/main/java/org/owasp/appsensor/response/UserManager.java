package org.owasp.appsensor.response;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;

/**
 * The UserManager is used by the client application as an interface that must
 * be implemented to handle certain {@link Response} actions. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface UserManager {
	
	/**
	 * Logout the User
	 * 
	 * @param user User to logout
	 */
	public void logout(User user);
	
	/**
	 * Disable (lock) the User
	 * 
	 * @param user User to disable (lock)
	 */
	public void disable(User user);
	
}
