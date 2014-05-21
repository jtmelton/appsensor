package org.owasp.appsensor.storage.jpa2;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.ResponseListener;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.storage.ResponseStore;
import org.owasp.appsensor.storage.jpa2.dao.ResponseRepository;
import org.owasp.appsensor.util.DateUtils;
import org.slf4j.Logger;

/**
 * This is a jpa2 implementation of the {@link ResponseStore}.
 * 
 * Implementations of the {@link ResponseListener} interface can register with 
 * this class and be notified when new {@link Response}s are added to the data store 
 * 
 * The implementation stores the {@link Response} in a jpa2 driven DB.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class Jpa2ResponseStore extends ResponseStore {

	private Logger logger;

	/** maintain a repository to read/write {@link Event}s from */
	@Inject 
	ResponseRepository responseRepository;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warn("Security response " + response + " triggered for user: " + response.getUser().getUsername());

		responseRepository.save(response);
		
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
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		for (Response response : responseRepository.findAll()) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(response.getDetectionSystemId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(response.getTimestamp())) : true;
					
			if (userMatch && detectionSystemMatch && earliestMatch) {
				matches.add(response);
			}
		}
		
		return matches;
	}
	
}
