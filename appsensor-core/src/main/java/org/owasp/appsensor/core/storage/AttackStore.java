package org.owasp.appsensor.core.storage;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.storage.AttackStoreListener;
import org.owasp.appsensor.core.util.DateUtils;

import javax.inject.Inject;
import java.util.Collection;
import java.util.HashSet;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A store is an observable object.
 *
 * It is watched by implementations of the {@link AttackListener} interfaces.
 *
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
public abstract class AttackStore {

	private static Collection<AttackListener> listeners = new CopyOnWriteArrayList<>();

	/**
	 * Add an attack to the AttackStore
	 *
	 * @param attack the {@link org.owasp.appsensor.core.Attack} object to add to the AttackStore
	 */
	public abstract void addAttack(Attack attack);

	/**
	 * Finder for attacks in the AttackStore.
	 *
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Attack} objects matching the search criteria.
	 */
	public abstract Collection<Attack> findAttacks(SearchCriteria criteria);

	/**
	 * Register an {@link AttackListener} to notify when {@link Attack}s are added
	 *
	 * @param listener the {@link AttackListener} to register
	 */
	public void registerListener(AttackListener listener) {
		if (! listeners.contains(listener)) {
			boolean unique = true;

			for (AttackListener existing : listeners) {
				if (existing.getClass().equals(listener.getClass())) {
					unique = false;
					break;
				}
			}

			if (unique) {
				listeners.add(listener);
			}
		}
	}

	/**
	 * Notify each {@link AttackListener} of the specified {@link Attack}
	 *
	 * @param response the {@link Attack} to notify each {@link AttackListener} about
	 */
	public void notifyListeners(Attack attack) {
		for (AttackListener listener : listeners) {
			listener.onAdd(attack);
		}
	}

	/**
	 * Automatically inject any {@link AttackStoreListener}s, which are implementations of
	 * {@link AttackListener} so they can be notified of changes.
	 *
	 * @param collection of {@link AttackListener}s that are injected to be
	 * 			listeners on the {@link @AttackStore}
	 */
	@Inject @AttackStoreListener
	public void setListeners(Collection<AttackListener> listeners) {
		for (AttackListener listener : listeners) {
			registerListener(listener);
		}
	}

	/**
	 * Finder for attacks in the AttackStore.
	 *
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @param attacks the {@link Attack} objects to match on - supplied by subclasses
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Attack} objects matching the search criteria.
	 */
	protected Collection<Attack> findAttacks(SearchCriteria criteria, Collection<Attack> attacks) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}

		Collection<Attack> matches = new HashSet<Attack>();

		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Rule rule = criteria.getRule();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());

		for (Attack attack : attacks) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;

			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ?
					detectionSystemIds.contains(attack.getDetectionSystem().getDetectionSystemId()) : true;

			//check detection point match if detection point specified
			boolean detectionPointMatch = true;
			if (detectionPoint != null) {
				detectionPointMatch = (attack.getDetectionPoint() != null) ?
						detectionPoint.typeAndThresholdMatches(attack.getDetectionPoint()) : false;
			}

			//check rule match if rule specified
			boolean ruleMatch = true;
			if (rule != null) {
				ruleMatch = (attack.getRule() != null) ?
					rule.guidMatches(attack.getRule()) : false;
			}

			DateTime attackTimestamp = DateUtils.fromString(attack.getTimestamp());

			boolean earliestMatch = (earliest != null) ?
					(earliest.isBefore(attackTimestamp) || earliest.isEqual(attackTimestamp))
					: true;

			if (userMatch && detectionSystemMatch && detectionPointMatch && ruleMatch && earliestMatch) {
				matches.add(attack);
			}
		}

		return matches;
	}

	/**
	 * Finder for attacks in the AttackStore.
	 *
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @param attack the {@link Attack} object to match on
	 * @return true or false depending on the matching of the search criteria to the {@link Attack}
	 */
	protected boolean isMatchingAttack(SearchCriteria criteria, Attack attack) {
		boolean match = false;

		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		Rule rule = criteria.getRule();

		// check user match if user specified
		boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;

		// check detection system match if detection systems specified
		boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ?
				detectionSystemIds.contains(attack.getDetectionSystem().getDetectionSystemId()) : true;

		// check detection point match if detection point specified
		boolean detectionPointMatch = (detectionPoint != null) ?
				detectionPoint.typeAndThresholdMatches(attack.getDetectionPoint()) : true;

		//check rule match if rule specified
		boolean ruleMatch = true;
		if (rule != null) {
			ruleMatch = (attack.getRule() != null) ?
				rule.guidMatches(attack.getRule()) : false;
		}

		boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(attack.getTimestamp())): true;

		if (userMatch && detectionSystemMatch && detectionPointMatch && ruleMatch && earliestMatch) {
			match = true;
		}

		return match;
	}

}