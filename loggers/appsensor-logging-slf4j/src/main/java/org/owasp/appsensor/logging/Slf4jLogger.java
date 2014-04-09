package org.owasp.appsensor.logging;

import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.slf4j.LoggerFactory;

/**
 * A simple pass-through {@link Logger} implementation using slf4j 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class Slf4jLogger implements org.owasp.appsensor.logging.Logger {
	
	private org.slf4j.Logger logger = LoggerFactory.getLogger(Slf4jLogger.class);

	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public org.owasp.appsensor.logging.Logger setLoggerClass(String className) {
		logger = LoggerFactory.getLogger(className);
		return this;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public org.owasp.appsensor.logging.Logger setLoggerClass(Class<?> clazz) {
		logger = LoggerFactory.getLogger(clazz);
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(String message) {
		logger.error(message);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(String message, Throwable throwable) {
		logger.error(message,throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(String message) {
		logger.warn(message);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(String message, Throwable throwable) {
		logger.warn(message,throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warning(String message) {
		logger.info(message);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warning(String message, Throwable throwable) {
		logger.info(message,throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(String message) {
		logger.debug(message);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(String message, Throwable throwable) {
		logger.debug(message,throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(String message) {
		logger.trace(message);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(String message, Throwable throwable) {
		logger.trace(message,throwable);
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
