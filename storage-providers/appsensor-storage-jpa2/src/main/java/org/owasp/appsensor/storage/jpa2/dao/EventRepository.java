package org.owasp.appsensor.storage.jpa2.dao;

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.owasp.appsensor.Event;
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
	
}
