package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.logging.Logger;

/**
 * This is the reference attack analysis engine, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link org.owasp.appsensor.Attack}
 * implementations. 
 * 
 * The implementation performs a simple analysis that checks the created attack against any created responses. 
 * It then creates a response and adds it to the {@link org.owasp.appsensor.storage.ResponseStore}. 
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceAttackAnalysisEngine implements AnalysisEngine {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceAttackAnalysisEngine.class);
	
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Attack) {
			Attack attack = (Attack)observedObject;
			
			DetectionPoint triggeringDetectionPoint = attack.getDetectionPoint();
			
			//grab any existing responses
			Collection<Response> existingResponses = 
					AppSensorServer.getInstance().getResponseStore().findResponses(
							attack.getUser(), 
							triggeringDetectionPoint,
							AppSensorServer.getInstance().getConfiguration().getRelatedDetectionSystems(attack.getDetectionSystemId())
							);

			Response response = findAppropriateResponse(triggeringDetectionPoint, existingResponses, attack);
			
			if (response != null) {
				logger.info("Response set for user <" + attack.getUser().getUsername() + "> - storing response action " + response.getAction());
				AppSensorServer.getInstance().getResponseStore().addResponse(response);
			}
		} 
	}
	
	protected Response findAppropriateResponse(DetectionPoint triggeringDetectionPoint, Collection<Response> existingResponses, Attack attack) {
		Response response = null;
		
		Collection<? extends Response> possibleResponses = findPossibleResponses(triggeringDetectionPoint);
		
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
	
	protected Collection<? extends Response> findPossibleResponses(DetectionPoint triggeringDetectionPoint) {
		Collection<? extends Response> possibleResponses = new ArrayList<Response>();
		
		for (DetectionPoint configuredDetectionPoint : AppSensorServer.getInstance().getConfiguration().getDetectionPoints()) {
			if (configuredDetectionPoint.getId().equals(triggeringDetectionPoint.getId())) {
				possibleResponses = configuredDetectionPoint.getResponses();
				break;
			}
		}
		
		return possibleResponses;
	}
	
	/**
	 * Test a given {@link org.owasp.appsensor.Response} to see if it's been executed before.
	 * 
	 * @param response response to test to see if it's been executed before
	 * @param existingResponses set of previously executed responses
	 * @return true if response has been executed before
	 */
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
