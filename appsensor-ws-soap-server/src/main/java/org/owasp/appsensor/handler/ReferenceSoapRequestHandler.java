package org.owasp.appsensor.handler;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This is the soap endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@WebService(
        portName = "SoapRequestHandlerPort",
        serviceName = "SoapRequestHandlerService",
        targetNamespace = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/wsdl",
        endpointInterface = "org.owasp.appsensor.handler.SoapRequestHandler")
@HandlerChain(file="handler-chain.xml")
public class ReferenceSoapRequestHandler implements SoapRequestHandler {

	public static String APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR = "APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR";
	
	@Resource 
	private WebServiceContext wsContext;
	
	/**
	 * {@inheritDoc}
	 */
	@WebMethod
	@Override
	public void addEvent(Event event) throws NotAuthorizedException {
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@WebMethod
	@Override
	public void addAttack(Attack attack) throws NotAuthorizedException {
		AppSensorServer.getInstance().getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@WebMethod
	@Override
	public Collection<Response> getResponses(long earliest) throws NotAuthorizedException {
		@SuppressWarnings("unchecked")
		Map<String, List<String>> httpHeaders = (Map<String, List<String>>) wsContext.getMessageContext().get(MessageContext.HTTP_REQUEST_HEADERS);
		
		String detectionSystemId = httpHeaders.get(APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR).get(0);
		
		return AppSensorServer.getInstance().getResponseStore().findResponses(detectionSystemId, earliest);
	}

}
