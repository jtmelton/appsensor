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

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * This is a repository/dao class for storing/retrieving {@link Event} objects 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Repository
@Transactional
public class EventRepository {

	@PersistenceContext
	private EntityManager em;
	
	public EventRepository() { }
	
	/**
	 * Save {@link Event} to DB
	 * 
	 * @param event {@link Event} to save
	 */
	@Transactional
	public void save(Event event) {
		Event merged = em.merge(event);
		em.flush();
		event.setId(merged.getId());
	}
	
	/**
	 * Search for {@link Event} by id
	 * 
	 * @param id id to search by
	 * @return single {@link Event} object found by id, or null if not exists
	 */
	@Transactional(readOnly = true)
	public Event find(Integer id) {
		return em.createQuery("FROM Event WHERE id = :id", Event.class)
				.setParameter("id", id)
				.getSingleResult();
	}
	
	/**
	 * Retrive all {@link Event}s from the DB
	 * 
	 * @return {@link Collection} of {@link Event}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Event> findAll() {
		return em.createQuery("FROM Event", Event.class).getResultList();
	}
	
	/**
	 * Retrive all {@link Event}s from the DB
	 * 
	 * @return {@link Collection} of {@link Event}s from the DB
	 */
	@Transactional(readOnly = true)
	public Collection<Event> find(SearchCriteria searchCriteria) {
		
//		if user exists, compare on [username]
//		if detection point exists, compare on [category, label, threshold count, threshold interval]
//		if detection system ids exist, do an "in"
//		if earliest exists, compare on [event date > earliest]
		
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<Event> criteriaQuery = criteriaBuilder.createQuery(Event.class);
		Root<Event> root = criteriaQuery.from(Event.class);
		
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

		TypedQuery<Event> query = em.createQuery(criteriaQuery); 
		List<Event> result = query.getResultList();
		
		return result;
	}
	
}
