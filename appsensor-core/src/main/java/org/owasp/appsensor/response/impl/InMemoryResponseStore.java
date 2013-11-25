package org.owasp.appsensor.response.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ResponseStore;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.User;

public class InMemoryResponseStore extends ResponseStore {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(InMemoryResponseStore.class);
	
	private Collection<Response> responses = new CopyOnWriteArrayList<Response>();
	
	@Override
	public void addResponse(Response response) {
		logger.warning("Security response " + response + " triggered for user: " + response.getUser().getUsername());
	    
		responses.add(response);
		
		super.setChanged();
		
		super.notifyObservers(response);
	}
	
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
