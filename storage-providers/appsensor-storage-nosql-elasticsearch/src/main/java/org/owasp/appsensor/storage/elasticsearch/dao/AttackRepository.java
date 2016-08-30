package org.owasp.appsensor.storage.elasticsearch.dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.util.List;

/**
 * This is a repository/dao class for storing/retrieving {@link Attack} objects
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */

@Repository
public class AttackRepository extends AbstractElasticRepository {

    private static final String ELASTIC_TYPE = "attack";


    public void save(Attack attack) throws JsonProcessingException {
        super.save(attack);
    }


    public List<Attack> findAttacksBySearchCriteria(SearchCriteria criteria) throws IOException {
        return findBySearchCriteria(criteria, Attack.class);
    }

    @Override
    protected String getElasticIndexType() {
        return ELASTIC_TYPE;
    }
}
