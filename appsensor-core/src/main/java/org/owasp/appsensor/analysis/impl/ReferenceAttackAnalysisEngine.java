package org.owasp.appsensor.analysis.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.AnalysisEngine;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

public class ReferenceAttackAnalysisEngine implements AnalysisEngine {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(ReferenceAttackAnalysisEngine.class);
	
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Attack) {
			Attack attack = (Attack)observedObject;
			
			DetectionPoint triggeringDetectionPoint = attack.getDetectionPoint();
			
			//grab any existing responses
			Collection<Response> existingResponses = 
					ServerObjectFactory.getResponseStore().findResponses(
							attack.getUser(), 
							triggeringDetectionPoint,
							ServerObjectFactory.getConfiguration().getRelatedDetectionSystems(attack.getDetectionSystemId())
							);

			Response response = findAppropriateResponse(triggeringDetectionPoint, existingResponses, attack);
			
			if (response != null) {
				logger.info("Response set for user <" + attack.getUser().getUsername() + "> - storing response action " + response.getAction());
				ServerObjectFactory.getResponseStore().addResponse(response);
			}
		} 
	}
	
	protected Response findAppropriateResponse(DetectionPoint triggeringDetectionPoint, Collection<Response> existingResponses, Attack attack) {
		Response response = null;
		
		Collection<Response> possibleResponses = findPossibleResponses(triggeringDetectionPoint);
		
		if (existingResponses == null) {
			//no responses yet, just grab first configured response from detection point
			response = possibleResponses.iterator().next();
		} else {
			for (Response configuredResponse : possibleResponses) {
				response = configuredResponse;
				
				if (! isPreviousResponse(response, existingResponses)) {
					//if we find that this response doesn't already exist, use it
					break;
				}
				
				//if we reach here, we will just use the last configured response (repeat last response)
			}
		}
		
		if(response == null) {
			throw new IllegalArgumentException("No appropriate response was configured for this detection point: " + triggeringDetectionPoint.getId());
		}
		
		//set extra fields
		response.setUser(attack.getUser());
		response.setDetectionPoint(triggeringDetectionPoint);
		response.setTimestamp(attack.getTimestamp());
		response.setDetectionSystemId(attack.getDetectionSystemId());
		
		return response;
	}
	
	protected Collection<Response> findPossibleResponses(DetectionPoint triggeringDetectionPoint) {
		Collection<Response> possibleResponses = new ArrayList<Response>();
		
		for (DetectionPoint configuredDetectionPoint : ServerObjectFactory.getConfiguration().getDetectionPoints()) {
			if (configuredDetectionPoint.getId().equals(triggeringDetectionPoint.getId())) {
				possibleResponses = configuredDetectionPoint.getResponses();
				break;
			}
		}
		
		return possibleResponses;
	}
	
	protected boolean isPreviousResponse(Response response, Collection<Response> existingResponses) {
		boolean previousResponse = false;
		
		for (Response existingResponse : existingResponses) {
			if (response.getAction().equals(existingResponse.getAction())) {
				previousResponse = true;
			}
		}
		
		return previousResponse;
	}
}
