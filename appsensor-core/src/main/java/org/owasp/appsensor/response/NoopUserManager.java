package org.owasp.appsensor.response;

import javax.inject.Named;

import org.owasp.appsensor.User;
import org.owasp.appsensor.logging.Loggable;
import org.slf4j.Logger;

/**
 * No-op user manager that is used most likely in test configurations. 
 * It is possible the response handler could handle these actions 
 * directly, but unlikely. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
@Named
@Loggable
public class NoopUserManager implements UserManager {

	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void logout(User user) {
		logger.info("The no-op user manager did not logout the user as requested.");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void disable(User user) {
		logger.info("The no-op user manager did not disable the user as requested.");
	}

}
