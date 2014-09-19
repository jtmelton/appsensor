package org.owasp.appsensor.storage.jpa2.dao;

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.owasp.appsensor.core.Attack;
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
	
}
