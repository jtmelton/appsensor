package org.owasp.appsensor.exceptions;

/**
 * This exception is meant to be thrown by the {@link org.owasp.appsensor.RequestHandler}
 * when a {@link org.owasp.appsensor.ClientApplication} is not providing appropriate
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
