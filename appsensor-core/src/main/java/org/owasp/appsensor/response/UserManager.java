package org.owasp.appsensor.response;

import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.Configurable;

/**
 * The UserManager is used by the client application as an interface that must
 * be implemented to handle certain {@link org.owasp.appsensor.Response} actions. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface UserManager extends Configurable {
	
	/**
	 * Logout the {@link org.owasp.appsensor.User}
	 * 
	 * @param user User to logout
	 */
	public void logout(User user);
	
	/**
	 * Disable (lock) the {@link org.owasp.appsensor.User}
	 * 
	 * @param user User to disable (lock)
	 */
	public void disable(User user);
	
}
