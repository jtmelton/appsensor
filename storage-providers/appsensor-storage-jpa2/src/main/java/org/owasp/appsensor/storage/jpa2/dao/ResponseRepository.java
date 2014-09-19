package org.owasp.appsensor.storage.jpa2.dao;

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.owasp.appsensor.core.Response;
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
	
}
