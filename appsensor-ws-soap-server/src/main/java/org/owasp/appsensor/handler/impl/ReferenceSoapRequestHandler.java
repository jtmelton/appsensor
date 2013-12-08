package org.owasp.appsensor.handler.impl;

import java.util.Collection;

import javax.jws.WebMethod;
import javax.jws.WebService;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

/**
 * This is the soap endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@WebService(
        portName = "SoapRequestHandlerPort",
        serviceName = "SoapRequestHandlerService",
        targetNamespace = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl",
        endpointInterface = "org.owasp.appsensor.handler.impl.SoapRequestHandler")
public class ReferenceSoapRequestHandler implements SoapRequestHandler {

	@WebMethod
	@Override
	public void addEvent(Event event) {
		ServerObjectFactory.getEventStore().addEvent(event);
	}

	@WebMethod
	@Override
	public void addAttack(Attack attack) {
		ServerObjectFactory.getAttackStore().addAttack(attack);
	}

	@WebMethod
	@Override
	public Collection<Response> getResponses(String detectionSystemId, long earliest) {
		return ServerObjectFactory.getResponseStore().findResponses(detectionSystemId, earliest);
	}

}
