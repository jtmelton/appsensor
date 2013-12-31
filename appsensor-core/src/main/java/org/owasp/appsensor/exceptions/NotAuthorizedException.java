package org.owasp.appsensor.exceptions;

public class NotAuthorizedException extends RuntimeException  {

	private static final long serialVersionUID = 3914161530293443363L;

	public NotAuthorizedException(String s) {
		super(s);
	}
	
	public NotAuthorizedException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
