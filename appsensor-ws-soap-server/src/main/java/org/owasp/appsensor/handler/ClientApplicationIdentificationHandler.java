package org.owasp.appsensor.handler;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.exceptions.NotAuthenticatedException;

public class ClientApplicationIdentificationHandler implements SOAPHandler<SOAPMessageContext> {
	
	/** default name for client application identification header */
	private static String HEADER_NAME = "X-Appsensor-Client-Application-Name";
	
	private static boolean checkedConfigurationHeaderName = false;
	
	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		//should only run on first request
		if (! checkedConfigurationHeaderName) {
			updateHeaderFromConfiguration();
			checkedConfigurationHeaderName = true;
		}
				
	    //check inbound headers
		if (! (Boolean)context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)) {
			
			@SuppressWarnings("unchecked")
			Map<String, List<String>> httpHeaders = (Map<String, List<String>>) context.get(MessageContext.HTTP_REQUEST_HEADERS);
			List<String> clientApplicationIdentifier = httpHeaders.get(HEADER_NAME);
			
			// Get the client application identifier passed in HTTP headers parameters
		    if (clientApplicationIdentifier == null || clientApplicationIdentifier.get(0) == null) {
		    	throw new NotAuthenticatedException("Access requires sending configured client application identification header.");
		    }
		    
		    //set the specific header for the client app
		    httpHeaders.put(ReferenceSoapRequestHandler.APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR, clientApplicationIdentifier);
		}

		return true;
	}

	private void updateHeaderFromConfiguration() {
		String configuredHeaderName = AppSensorServer.getInstance().getConfiguration().getClientApplicationIdentificationHeaderName();
		
		if (configuredHeaderName != null && configuredHeaderName.trim().length() > 0) {
			HEADER_NAME = configuredHeaderName;
		}
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
