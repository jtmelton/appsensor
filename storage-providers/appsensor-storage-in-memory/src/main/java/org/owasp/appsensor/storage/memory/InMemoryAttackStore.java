package org.owasp.appsensor.storage.memory;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
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

		logger.warn("Security attack " + attack.getName() + " triggered by user: " + attack.getUser().getUsername());

		attacks.add(attack);

		super.notifyListeners(attack);
	}

	public void clearAll() {
		attacks.clear();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		return findAttacks(criteria, attacks);
	}

}