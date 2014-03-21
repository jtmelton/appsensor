package org.owasp.appsensor.listener;

import org.owasp.appsensor.Response;

public interface ResponseListener {
	public void onAdd(Response response);
}
