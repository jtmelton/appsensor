package org.owasp.appsensor.analysis.impl;

import java.util.Observable;

import org.owasp.appsensor.AnalysisEngine;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.AppSensorServer;

/**
 * This is a reference response handler, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link org.owasp.appsensor.Response}
 * implementations. 
 * 
 * The implementation is trivial and simply delegates the work to the configured 
 * {@link org.owasp.appsensor.ResponseHandler} for processing.
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceResponseAnalysisEngine implements AnalysisEngine {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceResponseAnalysisEngine.class);
	
	/**
	 * This method simply catches responses and calls the 
	 * configured {@link org.owasp.appsensor.ResponseHandler} to process them. 
	 * 
	 * @param observable object that was being obeserved - ignored in this case
	 * @param observedObject object that was added to observable. In this case
	 * 			we are only interested if the object is 
	 * 			a {@link org.owasp.appsensor.Response} object
	 */
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Attack) {
			Response response = (Response)observedObject;
			
			if (response != null) {
				logger.info("Response executed for user <" + response.getUser().getUsername() + "> - executing response action " + response.getAction());
				
				AppSensorServer.getInstance().getResponseHandler().handle(response);
			}
		} 
	}
	
}
