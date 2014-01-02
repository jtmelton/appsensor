package org.owasp.appsensor.response;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.logging.Logger;

/**
 * This class is a simple NO-OP response handler. Calls to this response handler simply 
 * log the action to the configured logger. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class NoopResponseHandler implements ResponseHandler {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(NoopResponseHandler.class);
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handle(Response response) {
		logger.debug("NO-OP response handler invoked for action: " + response.getAction());
	}

}
