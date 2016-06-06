package org.owasp.appsensor.storage.jpa2;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.storage.jpa2.dao.AttackRepository;
import org.slf4j.Logger;

/**
 * This is a jpa2 implementation of the {@link AttackStore}.
 * 
 * Implementations of the {@link AttackListener} interface can register with 
 * this class and be notified when new {@link Attack}s are added to the data store 
 * 
 * The implementation stores the {@link Attack} in a jpa2 driven DB.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class Jpa2AttackStore extends AttackStore {
	
	private Logger logger;
	
	/** maintain a repository to read/write {@link Event}s from */
	@Inject 
	AttackRepository attackRepository;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warn("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());
	       
		attackRepository.save(attack);
		
		super.notifyListeners(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		Collection<Attack> attacksAllTimestamps = attackRepository.find(criteria);
		
		// timestamp stored as string not queryable in DB, all timestamps come back, still need to filter this subset		
		return findAttacks(criteria, attacksAllTimestamps);
	}
	
}
