package org.owasp.appsensor.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.logging.Logger;

/**
 * This is a reference implementation of the attack store, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link org.owasp.appsensor.Attack} implementations. 
 * 
 * The implementation is trivial and simply stores the {@link org.owasp.appsensor.Attack}s in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryAttackStore extends AttackStore {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryAttackStore.class);
	
	/** maintain a collection of {@link Attack}s as an in-memory list */
	private static Collection<Attack> attacks = new CopyOnWriteArrayList<Attack>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warning("Security attack " + attack.getDetectionPoint().getId() + " triggered by user: " + attack.getUser().getUsername());
	       
		attacks.add(attack);
		
		super.notifyListeners(attack);
//		super.setChanged();
//		
//		super.notifyObservers(attack);
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
		Long earliest = criteria.getEarliest();
		
		for (Attack attack : attacks) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(attack.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(attack.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.longValue() < attack.getTimestamp() : true;
			
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(attack);
			}
		}
		
		return matches;
	}
	
}
