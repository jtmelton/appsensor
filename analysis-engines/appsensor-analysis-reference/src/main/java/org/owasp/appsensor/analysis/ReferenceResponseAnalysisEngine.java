package org.owasp.appsensor.analysis;

import javax.inject.Named;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.storage.ResponseStore;
import org.slf4j.Logger;

/**
 * This is a reference {@link Response} analysis engine, 
 * and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link Response} class.
 * 
 * The implementation is trivial and simply logs the {@link Response}
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class ReferenceResponseAnalysisEngine extends ResponseAnalysisEngine {

	private Logger logger;
	
	/**
	 * This method simply logs responses.
	 * 
	 * @param response {@link Response} that has been added to the {@link ResponseStore}.
	 */
	@Override
	public void analyze(Response response) {
		if (response != null) {
			logger.info("NO-OP Response for user <" + response.getUser().getUsername() + "> - should be executing response action " + response.getAction());
		}
	}
	
}
