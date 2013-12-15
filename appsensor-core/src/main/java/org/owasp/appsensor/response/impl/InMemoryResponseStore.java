package org.owasp.appsensor.response.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ResponseStore;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.User;

/**
 * This is a reference implementation of the response store, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link org.owasp.appsensor.Response} implementations. 
 * 
 * The implementation is trivial and simply stores the Responses in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryResponseStore extends ResponseStore {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryResponseStore.class);
	
	private Collection<Response> responses = new CopyOnWriteArrayList<Response>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warning("Security response " + response + " triggered for user: " + response.getUser().getUsername());
	    
		responses.add(response);
		
		super.setChanged();
		
		super.notifyObservers(response);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(User user, DetectionPoint search, Collection<String> detectionSystemIds) {
		Collection<Response> matchingResponses = new ArrayList<Response>();
		
		for (Response response : responses) {
			if (user.equals(response.getUser()) && 
					detectionSystemIds.contains(response.getDetectionSystemId()) &&
					response.getDetectionPoint().getId().equals(search.getId())) {
				matchingResponses.add(response);
			}
		}
		
		return matchingResponses;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(String detectionSystemId, long earliest) {
		Collection<Response> matchingResponses = new ArrayList<Response>();
		
		for (Response response : responses) {
			if (detectionSystemId.equals(response.getDetectionSystemId()) && 
					earliest < response.getTimestamp()) {
				matchingResponses.add(response);
			}
		}
		
		return matchingResponses;
	}

}
