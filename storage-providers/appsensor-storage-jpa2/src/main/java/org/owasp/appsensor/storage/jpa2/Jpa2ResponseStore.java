package org.owasp.appsensor.storage.jpa2;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.storage.jpa2.dao.ResponseRepository;
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
		logger.warn("Security response " + response.getAction() + " triggered for user: " + response.getUser().getUsername());

		responseRepository.save(response);
		
		super.notifyListeners(response);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(SearchCriteria criteria) {
		Collection<Response> responsesAllTimestamps = responseRepository.find(criteria);
		
		// timestamp stored as string not queryable in DB, all timestamps come back, still need to filter this subset		
		return findResponses(criteria, responsesAllTimestamps);
	}
	
}
