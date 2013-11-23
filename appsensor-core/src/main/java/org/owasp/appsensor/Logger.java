package org.owasp.appsensor;

/**
 * This interface is meant to be implemented
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Logger {

	/**
	 * Set the name for meaningful class names in log messages
	 * 
	 * If your logger supports instantiating a logger with a class name, 
	 * the implementation should allow instantiation in this manner.
	 * Otherwise, a NOOP implementation is acceptable.
	 */
	public Logger setLoggerClass(String className);
	
	/** 
	 * Set the class for meaningful class names in log messages
	 * 
	 * If your logger supports instantiating a logger with a class name, 
	 * the implementation should allow instantiation in this manner.
	 * Otherwise, a NOOP implementation is acceptable.
	 */
	public Logger setLoggerClass(Class<?> clazz);
	
	/**
     * Log a fatal event
     * 
     * @param message 
     * 		the message to log
     */
	public void fatal(String message);
	
	/**
     * Log a fatal level security event
     * and also record the stack trace associated with the event.
     * 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	public void fatal(String message, Throwable throwable);

	/**
     * Log an error level security event
     * 
     * @param message 
     * 		the message to log
     */
	public void error(String message);
	
	/**
     * Log an error level security event
     * and also record the stack trace associated with the event.
     * 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	public void error(String message, Throwable throwable);

	/**
     * Log a warning level security event
     * 
     * @param message 
     * 		the message to log
     */
	public void warning(String message);
	
	/**
     * Log a warning level security event
     * and also record the stack trace associated with the event.
     * 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	public void warning(String message, Throwable throwable);

	/**
     * Log an info level security event
     * 
     * @param message 
     * 		the message to log
     */
	public void info(String message);
	
	/**
     * Log an info level security event
     * and also record the stack trace associated with the event.
     * 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	public void info(String message, Throwable throwable);

	/**
     * Log a debug level security event
     * 
     * @param message 
     * 		the message to log
     */
	public void debug(String message);
	
	/**
     * Log a debug level security event
     * and also record the stack trace associated with the event.
     * 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	public void debug(String message, Throwable throwable);
}
