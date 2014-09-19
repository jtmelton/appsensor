package org.owasp.appsensor.core.response;

import org.owasp.appsensor.core.User;

/**
 * The UserManager is used by the client application as an interface that must
 * be implemented to handle certain {@link org.owasp.appsensor.core.Response} actions. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface UserManager {
	
	/**
	 * Logout the {@link org.owasp.appsensor.core.User}
	 * 
	 * @param user User to logout
	 */
	public void logout(User user);
	
	/**
	 * Disable (lock) the {@link org.owasp.appsensor.core.User}
	 * 
	 * @param user User to disable (lock)
	 */
	public void disable(User user);
	
}
