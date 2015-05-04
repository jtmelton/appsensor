package org.owasp.appsensor.local.analysis;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.analysis.ResponseAnalysisEngine;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.response.ResponseHandler;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.slf4j.Logger;
import org.springframework.context.annotation.Primary;

/**
 * This is a local {@link Response} analysis engine, 
 * and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link Response} class.
 * 
 * The implementation is straightforward and simply passes the {@link Response}
 * to the configured response handler.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Primary
@Named
@Loggable
public class LocalResponseAnalysisEngine extends ResponseAnalysisEngine {

	private Logger logger;
	
	@Inject
	private ResponseHandler responseHandler;
	
	/**
	 * This method simply logs or executes responses.
	 * 
	 * @param response {@link Response} that has been added to the {@link ResponseStore}.
	 */
	@Override
	public void analyze(Response response) {
		if(response == null) {
			return;
		}
		
		if (ResponseHandler.LOG.equals(response.getAction())) {
			logger.info("Handling <log> response for user <{}>", response.getUser().getUsername());
		} else {
			logger.info("Delegating response for user <{}> to configured response handler <{}>", 
					response.getUser().getUsername(), responseHandler.getClass().getName());
			responseHandler.handle(response);
		}
		
	}
	
}
