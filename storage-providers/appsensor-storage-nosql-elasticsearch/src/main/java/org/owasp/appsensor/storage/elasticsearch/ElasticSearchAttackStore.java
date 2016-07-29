package org.owasp.appsensor.storage.elasticsearch;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.storage.elasticsearch.dao.AttackRepository;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.util.Collection;

/**
 * This is an Elasticsearch implementation of the {@link AttackStore}.
 * <p>
 * Implementations of the {@link AttackListener} interface can register with
 * this class and be notified when new {@link Attack}s are added to the data store
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@Named
@Loggable
public class ElasticSearchAttackStore extends AttackStore {

    private Logger logger;

    @Inject
    private AttackRepository attackRepository;

    /**
     * {@inheritDoc}
     */
    @Override
    public void addAttack(Attack attack) {
        logger.warn("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());


        try {
            attackRepository.save(attack);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

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


        try {
            return attackRepository.findAttacksBySearchCriteria(criteria);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
