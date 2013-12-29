package org.owasp.appsensor.handler.impl;

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

public class RegisterClientApplicationIdentificationHandler implements
		SOAPHandler<SOAPMessageContext> {

	/** default name for client application identification header */
	private static String HEADER_NAME = "X-Appsensor-Client-Application-Name";

	private static boolean checkedConfigurationHeaderName = false;

	@Override
	public boolean handleMessage(SOAPMessageContext context) {

		//make sure this is an outbound request
		if ((Boolean)context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)) {
			// should only run on first request
			if (!checkedConfigurationHeaderName) {
				updateHeaderFromConfiguration();
				checkedConfigurationHeaderName = true;
			}
			
			@SuppressWarnings("unchecked")
			Map<String, List<String>> httpHeaders = (Map<String, List<String>>) context.get(MessageContext.HTTP_REQUEST_HEADERS);
			if (null == httpHeaders) {
				httpHeaders = new HashMap<String, List<String>>();
			}
			
			httpHeaders.put(HEADER_NAME, Collections.singletonList(AppSensorClient.getInstance().getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderValue()));
			context.put(MessageContext.HTTP_REQUEST_HEADERS, httpHeaders);
		}
		return true;
	}

	private void updateHeaderFromConfiguration() {
		String configuredHeaderName = AppSensorClient.getInstance().getConfiguration().getServerConnection().getClientApplicationIdentificationHeaderName();
		
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
