package org.owasp.appsensor.core.analysis;

import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.core.storage.ResponseStoreListener;

/**
 * The response analysis engine is an implementation of the Observer pattern. 
 * 
 * In this case the analysis engines watches the {@link ResponseStore} interface.
 * 
 * AnalysisEngine implementations are the components of AppSensor that 
 * constitute the "brain" of the system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@ResponseStoreListener
public abstract class ResponseAnalysisEngine implements ResponseListener {

	public void onAdd(Response response) {
		analyze(response);
	}
	
	public abstract void analyze(Response response);
	
}
