package org.owasp.appsensor.response;

import javax.inject.Named;

import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.response.ResponseHandler;

@Named
public class NoopResponseHandler implements ResponseHandler {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handle(Response response) {
		//
	}

}
