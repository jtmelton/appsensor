package org.owasp.appsensor.response;

import org.owasp.appsensor.Response;
import org.slf4j.Logger;

/**
 * This class is a simple NO-OP {@link Response} handler. Calls to this {@link Response} handler simply 
 * log the action to the configured logger. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NoopResponseHandler implements ResponseHandler {

	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handle(Response response) {
		logger.debug("NO-OP response handler invoked for action: " + response.getAction());
	}

}
