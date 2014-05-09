package org.owasp.appsensor.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.AttackListener;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.util.DateUtils;
import org.slf4j.Logger;

/**
 * This is a reference implementation of the {@link AttackStore}.
 * 
 * Implementations of the {@link AttackListener} interface can register with 
 * this class and be notified when new {@link Attack}s are added to the data store 
 * 
 * The implementation is trivial and simply stores the {@link Attack} in an in-memory collection.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class InMemoryAttackStore extends AttackStore {
	
	private Logger logger;
	
	/** maintain a collection of {@link Attack}s as an in-memory list */
	private static Collection<Attack> attacks = new CopyOnWriteArrayList<Attack>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warn("Security attack " + attack.getDetectionPoint().getId() + " triggered by user: " + attack.getUser().getUsername());
	       
		attacks.add(attack);
		
		super.notifyListeners(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Attack> matches = new ArrayList<Attack>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		for (Attack attack : attacks) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(attack.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(attack.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(attack.getTimestamp())) : true;
					
					
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(attack);
			}
		}
		
		return matches;
	}
	
}
