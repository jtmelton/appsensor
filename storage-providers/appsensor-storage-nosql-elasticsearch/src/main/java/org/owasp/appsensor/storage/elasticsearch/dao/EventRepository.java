package org.owasp.appsensor.storage.elasticsearch.dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.util.List;

/**
 * This is a repository/dao class for storing/retrieving {@link Event} objects
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */

@Repository
public class EventRepository extends AbstractElasticRepository {

    private static final String ELASTIC_TYPE = "event";


    public void save(Event event) throws JsonProcessingException {
        super.save(event);
    }


    public List<Event> findEventsBySearchCriteria(SearchCriteria criteria) throws IOException {
        return findBySearchCriteria(criteria, Event.class);
    }

    @Override
    protected String getElasticIndexType() {
        return ELASTIC_TYPE;
    }
}
