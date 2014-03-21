package org.owasp.appsensor.analysis;

import java.util.Observer;

import org.owasp.appsensor.AppSensorClient;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.listener.ResponseListener;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.response.ResponseHandler;

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
	 * @param observable object that was being obeserved - ignored in this case
	 * @param observedObject object that was added to observable. In this case
	 * 			we are only interested if the object is 
	 * 			a {@link Response} object
	 */
	@Override
	public void onAdd(Response response) {
//		if (observedObject instanceof Attack) {
//			Response response = (Response)observedObject;
//			
			if (response != null) {
				logger.info("Response executed for user <" + response.getUser().getUsername() + "> - executing response action " + response.getAction());
				
				AppSensorClient.getInstance().getResponseHandler().handle(response);
			}
//		} 
	}
//	public void update(Observable observable, Object observedObject) {
//		if (observedObject instanceof Attack) {
//			Response response = (Response)observedObject;
//			
//			if (response != null) {
//				logger.info("Response executed for user <" + response.getUser().getUsername() + "> - executing response action " + response.getAction());
//				
//				AppSensorClient.getInstance().getResponseHandler().handle(response);
//			}
//		} 
//	}
	
}
