package org.owasp.appsensor.storage.jpa2.dao;

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.owasp.appsensor.Response;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class ResponseRepository {

	@PersistenceContext
	private EntityManager em;
	
	public ResponseRepository() { }
	
	@Transactional
	public void save(Response response) {
		Response merged = em.merge(response);
		em.flush();
		response.setId(merged.getId());
	}
	
	@Transactional(readOnly = true)
	public Response find(Integer id) {
		return em.createQuery("FROM Response WHERE id = :id", Response.class)
				.setParameter("id", id)
				.getSingleResult();
	}
	
	@Transactional(readOnly = true)
	public Collection<Response> findAll() {
		return em.createQuery("FROM Response", Response.class).getResultList();
	}
	
}
