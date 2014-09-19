package org.owasp.appsensor.core.exceptions;

/**
 * This exception is thrown by the {@link org.owasp.appsensor.core.accesscontrol.AccessController}
 * when a {@link org.owasp.appsensor.core.ClientApplication} is not authorized to perform a 
 * specific action
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NotAuthorizedException extends RuntimeException  {

	private static final long serialVersionUID = 3914161530293443363L;

	public NotAuthorizedException(String s) {
		super(s);
	}
	
	public NotAuthorizedException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
