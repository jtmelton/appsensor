package org.owasp.appsensor.response;

import javax.inject.Named;

import org.owasp.appsensor.Response;

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
