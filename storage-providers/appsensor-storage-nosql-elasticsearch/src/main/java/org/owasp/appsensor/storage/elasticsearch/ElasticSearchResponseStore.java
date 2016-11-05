package org.owasp.appsensor.storage.elasticsearch;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.storage.elasticsearch.dao.ResponseRepository;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.util.Collection;

/**
 * This is a Elasticsearch implementation of the {@link ResponseStore}.
 * <p>
 * Implementations of the {@link ResponseListener} interface can register with
 * this class and be notified when new {@link Response}s are added to the data store
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@Named
@Loggable
public class ElasticSearchResponseStore extends ResponseStore {

    private Logger logger;

    @Inject
    private ResponseRepository responseRepository;


    /**
     * {@inheritDoc}
     */
    @Override
    public void addResponse(Response response) {
        logger.warn("Security response " + response.getAction() + " triggered for user: " + response.getUser().getUsername());


        try {
            responseRepository.save(response);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        super.notifyListeners(response);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Response> findResponses(SearchCriteria criteria) {
        try {
            return responseRepository.findResponsesBySearchCriteria(criteria);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
