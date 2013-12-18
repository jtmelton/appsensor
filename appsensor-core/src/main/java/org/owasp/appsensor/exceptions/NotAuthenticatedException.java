package org.owasp.appsensor.exceptions;

public class NotAuthenticatedException extends RuntimeException  {

	private static final long serialVersionUID = 538520201225584981L;

	public NotAuthenticatedException(String s) {
		super(s);
	}
	
	public NotAuthenticatedException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
