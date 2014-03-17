package org.owasp.appsensor.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.logging.Logger;

/**
 * This is a reference implementation of the response store, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link org.owasp.appsensor.Response} implementations. 
 * 
 * The implementation is trivial and simply stores the {@link org.owasp.appsensor.Response}s in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryResponseStore extends ResponseStore {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryResponseStore.class);
	
	/** maintain a collection of {@link Response}s as an in-memory list */
	private static Collection<Response> responses = new CopyOnWriteArrayList<Response>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warning("Security response " + response + " triggered for user: " + response.getUser().getUsername());

		responses.add(response);
		
		super.setChanged();
		
		super.notifyObservers(response);
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
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		Long earliest = criteria.getEarliest();
		
		for (Response response : responses) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(response.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(response.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.longValue() < response.getTimestamp() : true;
			
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(response);
			}
		}
		
		return matches;
	}
	
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds, Long earliest) {
//		Collection<Response> matches = new ArrayList<Response>();
//		
////		System.err.println("yaaaaaa");
//		for (Response response : responses) {
////			System.err.println("yo");
//			//check user match if user specified
//			boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
//			
//			//check detection system match if detection systems specified
//			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
//					detectionSystemIds.contains(response.getDetectionSystemId()) : true;
//			
//			//check detection point match if detection point specified
//			boolean detectionPointMatch = (detectionPoint != null) ? 
//					detectionPoint.getId().equals(response.getDetectionPoint().getId()) : true;
//			
//			boolean earliestMatch = (earliest != null) ? earliest.longValue() < response.getTimestamp() : true;
//			
//			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
//				matches.add(response);
//			}
//		}
//		
//		return matches;
//	}
//	
//	@Override
//	public Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds) {
//		return findResponses(user, detectionPoint, detectionSystemIds, null);
//	}
//	
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Response> findResponses(String detectionSystemId, Long earliest) {
//		Collection<String> detectionSystemIds = new ArrayList<String>();
//		detectionSystemIds.add(detectionSystemId);
//		
//		return findResponses(null, null, detectionSystemIds, earliest);
//	}
//	
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Response> findResponses(Long earliest) {
//		return findResponses(null, null, null, earliest);
//	}

}
