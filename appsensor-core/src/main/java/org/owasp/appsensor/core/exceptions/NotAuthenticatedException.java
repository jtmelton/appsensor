package org.owasp.appsensor.core.exceptions;

/**
 * This exception is meant to be thrown by the {@link org.owasp.appsensor.core.RequestHandler}
 * when a {@link org.owasp.appsensor.core.ClientApplication} is not providing appropriate
 * authentication credentials
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NotAuthenticatedException extends RuntimeException  {

	private static final long serialVersionUID = 538520201225584981L;

	public NotAuthenticatedException(String s) {
		super(s);
	}
	
	public NotAuthenticatedException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
