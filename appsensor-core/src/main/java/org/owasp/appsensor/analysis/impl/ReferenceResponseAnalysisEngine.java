package org.owasp.appsensor.analysis.impl;

import java.util.Observable;

import org.owasp.appsensor.AnalysisEngine;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

public class ReferenceResponseAnalysisEngine implements AnalysisEngine {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(ReferenceResponseAnalysisEngine.class);
	
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Attack) {
			Response response = (Response)observedObject;
			
			if (response != null) {
				logger.info("Response executed for user <" + response.getUser().getUsername() + "> - executing response action " + response.getAction());
				
				ServerObjectFactory.getResponseHandler().handle(response);
			}
		} 
	}
	
}
