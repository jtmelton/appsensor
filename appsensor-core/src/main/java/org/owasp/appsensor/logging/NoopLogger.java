package org.owasp.appsensor.logging;

/**
 * A simple no-op {@link Logger} implementation for those that need it. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NoopLogger implements org.owasp.appsensor.logging.Logger {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public org.owasp.appsensor.logging.Logger setLoggerClass(String className) {
		return null;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public org.owasp.appsensor.logging.Logger setLoggerClass(Class<?> clazz) {
		return null;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(String message) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(String message, Throwable throwable) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(String message) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(String message, Throwable throwable) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warning(String message) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warning(String message, Throwable throwable) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(String message) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(String message, Throwable throwable) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(String message) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(String message, Throwable throwable) { }

}
