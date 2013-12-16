package org.owasp.appsensor.exceptions;

public class NotBootstrappedException extends RuntimeException  {

	private static final long serialVersionUID = -4979426569444237055L;

	public NotBootstrappedException(String s) {
		super(s);
	}
	
	public NotBootstrappedException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
