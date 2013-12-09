package org.owasp.appsensor.handler;

import java.util.Collection;

import javax.jws.WebService;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;

/**
 * This is the soap endpoint interface for handling requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@WebService(targetNamespace = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl")
public interface SoapRequestHandler extends RequestHandler {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event);

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack);

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String detectionSystemId, long earliest);

}
