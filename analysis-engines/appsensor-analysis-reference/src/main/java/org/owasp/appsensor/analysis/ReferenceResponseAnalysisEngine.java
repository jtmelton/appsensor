package org.owasp.appsensor.analysis;

import java.util.Observer;

import org.owasp.appsensor.AppSensorClient;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.listener.ResponseListener;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.response.ResponseHandler;
import org.owasp.appsensor.storage.ResponseStore;

/**
 * This is a reference {@link Response} handler, and is an implementation of the {@link Observer} pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link Response}
 * implementations. 
 * 
 * The implementation is trivial and simply delegates the work to the configured 
 * {@link ResponseHandler} for processing.
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceResponseAnalysisEngine implements AnalysisEngine, ResponseListener {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceResponseAnalysisEngine.class);
	
	/**
	 * This method simply catches responses and calls the 
	 * configured {@link ResponseHandler} to process them. 
	 * 
	 * @param response {@link Response} that has been added to the {@link ResponseStore}.
	 */
	@Override
	public void onAdd(Response response) {
		if (response != null) {
			logger.info("Response executed for user <" + response.getUser().getUsername() + "> - executing response action " + response.getAction());
			
			AppSensorClient.getInstance().getResponseHandler().handle(response);
		}
	}
	
}
