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
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * This is a repository/dao class for storing/retrieving {@link Attack} objects 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Repository
@Transactional
public class AttackRepository {

	@PersistenceContext
	private EntityManager em;
	
	public AttackRepository() { }
	
	/**
	 * Save {@link Attack} to DB
	 * 
	 * @param attack {@link Attack} to save
	 */
	@Transactional
	public void save(Attack attack) {
		Attack merged = em.merge(attack);
		em.flush();
		attack.setId(merged.getId());
	}
	
	/**
	 * Search for {@link Attack} by id
	 * 
	 * @param id id to search by
	 * @return single {@link Attack} object found by id, or null if not exists
	 */
	@Transactional(readOnly = true)
	public Attack find(Integer id) {
		return em.createQuery("FROM Attack WHERE id = :id", Attack.class)
				.setParameter("id", id)
				.getSingleResult();
	}
	
	/**
	 * Retrive all {@link Attack}s from the DB
	 * 
	 * @return {@link Collection} of {@link Attack}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Attack> findAll() {
		return em.createQuery("FROM Attack", Attack.class).getResultList();
	}
	
	/**
	 * Retrive all {@link Attack}s from the DB matching criteria
	 * 
	 * @return {@link Collection} of {@link Attack}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Attack> find(SearchCriteria searchCriteria) {
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<Attack> criteriaQuery = criteriaBuilder.createQuery(Attack.class);
		Root<Attack> root = criteriaQuery.from(Attack.class);
		
		Collection<Predicate> conditions = new ArrayList<>();
		
		if (searchCriteria.getUser() != null) {
			Predicate userCondition = criteriaBuilder.equal(root.get("user").get("username"), searchCriteria.getUser().getUsername());
			conditions.add(userCondition);
		}
		
		if (searchCriteria.getDetectionPoint() != null) {
			
			if (searchCriteria.getDetectionPoint().getCategory() != null) {
				Predicate categoryCondition = criteriaBuilder.equal(root.get("detectionPoint").get("category"), 
						searchCriteria.getDetectionPoint().getCategory());
				conditions.add(categoryCondition);
			}
			
			if (searchCriteria.getDetectionPoint().getLabel() != null) {
				Predicate labelCondition = criteriaBuilder.equal(root.get("detectionPoint").get("label"), 
						searchCriteria.getDetectionPoint().getLabel());
				conditions.add(labelCondition);
			}
			
			if (searchCriteria.getDetectionPoint().getThreshold() != null) {
				
				if (searchCriteria.getDetectionPoint().getThreshold().getCount() > 0) {
					Predicate countCondition = criteriaBuilder.equal(root.get("detectionPoint").get("threshold").get("count"), 
							searchCriteria.getDetectionPoint().getThreshold().getCount());
					conditions.add(countCondition);
				}
				
				if (searchCriteria.getDetectionPoint().getThreshold().getInterval() != null) {
					if (searchCriteria.getDetectionPoint().getThreshold().getInterval().getUnit() != null) {
						Predicate durationCondition = criteriaBuilder.equal(root.get("detectionPoint").get("threshold").get("interval").get("duration"), 
								searchCriteria.getDetectionPoint().getThreshold().getInterval().getDuration());
						conditions.add(durationCondition);
					}
					
					if (searchCriteria.getDetectionPoint().getThreshold().getInterval().getDuration() > 0) {
						Predicate unitCondition = criteriaBuilder.equal(root.get("detectionPoint").get("threshold").get("interval").get("unit"), 
								searchCriteria.getDetectionPoint().getThreshold().getInterval().getUnit());
						conditions.add(unitCondition);
					}
				}
				
			}
			
		}
		
		if (searchCriteria.getDetectionSystemIds() != null) {
			Predicate detectionSystemCondition = root.get("detectionSystem").get("detectionSystemId").in(searchCriteria.getDetectionSystemIds());
			conditions.add(detectionSystemCondition);
		}

		if (conditions.size() > 0) {
			criteriaQuery.where(criteriaBuilder.and(conditions.toArray(new Predicate[0])));
		}
		
		criteriaQuery.orderBy(criteriaBuilder.asc(root.get("timestamp")));

		TypedQuery<Attack> query = em.createQuery(criteriaQuery); 
		List<Attack> result = query.getResultList();
		
		return result;
	}
	
}
