package org.owasp.appsensor.logging.impl;

import org.slf4j.LoggerFactory;

public class Slf4jLogger implements org.owasp.appsensor.Logger {
	
	private org.slf4j.Logger logger = LoggerFactory.getLogger(Slf4jLogger.class);

	@Override
	public org.owasp.appsensor.Logger setLoggerClass(String className) {
		logger = LoggerFactory.getLogger(className);
		return this;
	}
	
	@Override
	public org.owasp.appsensor.Logger setLoggerClass(Class<?> clazz) {
		logger = LoggerFactory.getLogger(clazz);
		return this;
	}
	
	@Override
	public void fatal(String message) {
		logger.error(message);
	}

	@Override
	public void fatal(String message, Throwable throwable) {
		logger.error(message,throwable);
	}

	@Override
	public void error(String message) {
		logger.warn(message);
	}

	@Override
	public void error(String message, Throwable throwable) {
		logger.warn(message,throwable);
	}

	@Override
	public void warning(String message) {
		logger.info(message);
	}

	@Override
	public void warning(String message, Throwable throwable) {
		logger.info(message,throwable);
	}

	@Override
	public void info(String message) {
		logger.debug(message);
	}

	@Override
	public void info(String message, Throwable throwable) {
		logger.debug(message,throwable);
	}

	@Override
	public void debug(String message) {
		logger.trace(message);
	}

	@Override
	public void debug(String message, Throwable throwable) {
		logger.trace(message,throwable);
	}

}
