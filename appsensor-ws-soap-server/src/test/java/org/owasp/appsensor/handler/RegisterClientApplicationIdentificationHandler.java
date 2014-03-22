package org.owasp.appsensor.handler;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.owasp.appsensor.AppSensorClient;

/**
 * This is the jax-ws SOAP handler that adds authentication info 
 * of client applications to outbound requests 
 * 
 * The authentication mechanism involves adding an HTTP request header 
 * for the username of the given client application. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class RegisterClientApplicationIdentificationHandler implements
		SOAPHandler<SOAPMessageContext> {

	/** default name for client application identification header */
	private static String HEADER_NAME = "X-Appsensor-Client-Application-Name";

	@Override
	public boolean handleMessage(SOAPMessageContext context) {

		//make sure this is an outbound request
		if ((Boolean)context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)) {
			
			@SuppressWarnings("unchecked")
			Map<String, List<String>> httpHeaders = (Map<String, List<String>>) context.get(MessageContext.HTTP_REQUEST_HEADERS);
			if (null == httpHeaders) {
				httpHeaders = new HashMap<String, List<String>>();
			}
			
			String clientApplicationName = AppSensorClient.getInstance().getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue();
			
			httpHeaders.put(HEADER_NAME, Collections.singletonList(clientApplicationName));
			context.put(MessageContext.HTTP_REQUEST_HEADERS, httpHeaders);
		}
		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
		//
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}

}
