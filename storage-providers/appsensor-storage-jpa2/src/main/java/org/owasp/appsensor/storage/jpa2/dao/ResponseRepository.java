package org.owasp.appsensor.storage.jpa2.dao;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.util.DateUtils;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * This is a repository/dao class for storing/retrieving {@link Response} objects 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Repository
@Transactional
public class ResponseRepository {

	@PersistenceContext
	private EntityManager em;
	
	public ResponseRepository() { }
	
	/**
	 * Save {@link Response} to DB
	 * 
	 * @param response {@link Response} to save
	 */
	@Transactional
	public void save(Response response) {
		Response merged = em.merge(response);
		em.flush();
		response.setId(merged.getId());
	}
	
	/**
	 * Search for {@link Response} by id
	 * 
	 * @param id id to search by
	 * @return single {@link Response} object found by id, or null if not exists
	 */
	@Transactional(readOnly = true)
	public Response find(Integer id) {
		return em.createQuery("FROM Response WHERE id = :id", Response.class)
				.setParameter("id", id)
				.getSingleResult();
	}
	
	/**
	 * Retrive all {@link Response}s from the DB
	 * 
	 * @return {@link Collection} of {@link Response}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Response> findAll() {
		return em.createQuery("FROM Response", Response.class).getResultList();
	}
	
	/**
	 * Retrive all {@link Response}s from the DB matching criteria
	 * 
	 * @return {@link Collection} of {@link Response}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Response> find(SearchCriteria searchCriteria) {
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<Response> criteriaQuery = criteriaBuilder.createQuery(Response.class);
		Root<Response> root = criteriaQuery.from(Response.class);
		
		Collection<Predicate> conditions = new ArrayList<>();
		
		if (searchCriteria.getUser() != null) {
			Predicate userCondition = criteriaBuilder.equal(root.get("user").get("username"), searchCriteria.getUser().getUsername());
			conditions.add(userCondition);
		}
		
		if (searchCriteria.getDetectionSystemIds() != null) {
			Predicate detectionSystemCondition = root.get("detectionSystem").get("detectionSystemId").in(searchCriteria.getDetectionSystemIds());
			conditions.add(detectionSystemCondition);
		}

		if (conditions.size() > 0) {
			criteriaQuery.where(criteriaBuilder.and(conditions.toArray(new Predicate[0])));
		}
		
		criteriaQuery.orderBy(criteriaBuilder.asc(root.get("timestamp")));

		TypedQuery<Response> query = em.createQuery(criteriaQuery); 
		List<Response> result = query.getResultList();
		
		return result;
	}
	
}
