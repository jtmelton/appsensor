package org.owasp.appsensor.handler;

import java.util.Collection;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This is the local endpoint that handles requests on the server-side.
 * 
 * Since this is a local implementation, there is no need for access control.
 * There are no requests coming from anywhere other than self, so it's trusted. 
 * 
 * Additionally, client/server is actually just an API call in the same JVM instance, 
 * but is separated to maintain the architectural design. Simple delegation 
 * lets us use the same pattern here. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class LocalRequestHandler implements RequestHandler {

	private static String detectionSystemId = null;	//start with blank
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) throws NotAuthorizedException {
		if (detectionSystemId == null) {
			detectionSystemId = event.getDetectionSystemId();
		}
		
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) throws NotAuthorizedException {
		if (detectionSystemId == null) {
			detectionSystemId = attack.getDetectionSystemId();
		}
		
		AppSensorServer.getInstance().getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(long earliest) throws NotAuthorizedException {
		return AppSensorServer.getInstance().getResponseStore().findResponses(detectionSystemId != null ? detectionSystemId : "", earliest);
	}
}