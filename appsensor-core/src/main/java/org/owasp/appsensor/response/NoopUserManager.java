package org.owasp.appsensor.response;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.logging.Logger;

/**
 * No-op user manager that is used most likely in test configurations. 
 * It is possible the response handler could handle these actions 
 * directly, but unlikely. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
public class NoopUserManager implements UserManager {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(NoopUserManager.class);
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
