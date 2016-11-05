package org.owasp.appsensor.storage.elasticsearch;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.storage.elasticsearch.dao.EventRepository;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.util.Collection;

/**
 * This is an Elasticsearch implementation of the {@link EventStore}.
 * <p>
 * Implementations of the {@link EventListener} interface can register with
 * this class and be notified when new {@link Event}s are added to the data store
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@Named
@Loggable
public class ElasticSearchEventStore extends EventStore {

    @Inject
    private EventRepository eventRepository;

    private Logger logger;

    /**
     * {@inheritDoc}
     */
    @Override
    public void addEvent(Event event) {
        logger.warn("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());

        try {
            eventRepository.save(event);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        super.notifyListeners(event);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Event> findEvents(SearchCriteria criteria) {
        if (criteria == null) {
            throw new IllegalArgumentException("criteria must be non-null");
        }

        try {
            return eventRepository.findEventsBySearchCriteria(criteria);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
