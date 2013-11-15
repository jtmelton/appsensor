package org.owasp.appsensor;

import java.util.Collection;
import java.util.Observable;

public abstract class ResponseStore extends Observable {
	public abstract void addResponse(Response response);
	public abstract Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
	public abstract Collection<Response> findResponses(String detectionSystemId, long earliest);
}
