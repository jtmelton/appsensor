package org.owasp.appsensor.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.ResponseListener;
import org.owasp.appsensor.logging.Logger;

/**
 * This is a reference implementation of the {@link ResponseStore}.
 * 
 * Implementations of the {@link ResponseListener} interface can register with 
 * this class and be notified when new {@link Response}s are added to the data store 
 * 
 * The implementation is trivial and simply stores the {@link Response} in an in-memory collection.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryResponseStore extends ResponseStore {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryResponseStore.class);

	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
	/** maintain a collection of {@link Response}s as an in-memory list */
	private static Collection<Response> responses = new CopyOnWriteArrayList<Response>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warning("Security response " + response + " triggered for user: " + response.getUser().getUsername());

		responses.add(response);
		
		super.notifyListeners(response);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Response> matches = new ArrayList<Response>();
		
		User user = criteria.getUser();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		Long earliest = criteria.getEarliest();
		
		for (Response response : responses) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(response.getDetectionSystemId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.longValue() < response.getTimestamp() : true;
			
			if (userMatch && detectionSystemMatch && earliestMatch) {
				matches.add(response);
			}
		}
		
		return matches;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
