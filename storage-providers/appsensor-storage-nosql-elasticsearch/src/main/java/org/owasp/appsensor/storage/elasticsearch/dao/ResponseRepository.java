package org.owasp.appsensor.storage.elasticsearch.dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.util.List;

/**
 * This is a repository/dao class for storing/retrieving {@link Response} objects
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */

@Repository
public class ResponseRepository extends AbstractElasticRepository {

    private static final String ELASTIC_TYPE = "response";


    public void save(Response response) throws JsonProcessingException {
        super.save(response);
    }


    public List<Response> findResponsesBySearchCriteria(SearchCriteria criteria) throws IOException {
        return findBySearchCriteria(criteria, Response.class);
    }

    @Override
    protected String getElasticIndexType() {
        return ELASTIC_TYPE;
    }
}
