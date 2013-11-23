package org.owasp.appsensor.logging.impl;

/**
 * A simple no-op logger implementation for those that need it. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NoopLogger implements org.owasp.appsensor.Logger {

	@Override
	public org.owasp.appsensor.Logger setLoggerClass(String className) {
		return null;
	}
	
	@Override
	public org.owasp.appsensor.Logger setLoggerClass(Class<?> clazz) {
		return null;
	}
	
	@Override
	public void fatal(String message) { }

	@Override
	public void fatal(String message, Throwable throwable) { }

	@Override
	public void error(String message) { }

	@Override
	public void error(String message, Throwable throwable) { }

	@Override
	public void warning(String message) { }

	@Override
	public void warning(String message, Throwable throwable) { }

	@Override
	public void info(String message) { }

	@Override
	public void info(String message, Throwable throwable) { }

	@Override
	public void debug(String message) { }

	@Override
	public void debug(String message, Throwable throwable) { }

}
