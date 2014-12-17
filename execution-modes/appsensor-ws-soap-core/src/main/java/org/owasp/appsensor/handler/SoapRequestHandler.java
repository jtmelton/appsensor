package org.owasp.appsensor.handler;

import java.util.Collection;

import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.RequestHandler;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;

/**
 * This is the soap endpoint interface for handling requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@WebService(targetNamespace = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl")
@SOAPBinding(style = SOAPBinding.Style.DOCUMENT, use=SOAPBinding.Use.LITERAL, parameterStyle=SOAPBinding.ParameterStyle.WRAPPED) 
public interface SoapRequestHandler extends RequestHandler {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) throws NotAuthorizedException;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) throws NotAuthorizedException;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) throws NotAuthorizedException;

}
