package org.owasp.appsensor.storage.jpa2.dao;

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.owasp.appsensor.Attack;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class AttackRepository {

	@PersistenceContext
	private EntityManager em;
	
	public AttackRepository() { }
	
	@Transactional
	public void save(Attack attack) {
		Attack merged = em.merge(attack);
		em.flush();
		attack.setId(merged.getId());
	}
	
	@Transactional(readOnly = true)
	public Attack find(Integer id) {
		return em.createQuery("FROM Attack WHERE id = :id", Attack.class)
				.setParameter("id", id)
				.getSingleResult();
	}
	
	@Transactional(readOnly = true)
	public Collection<Attack> findAll() {
		return em.createQuery("FROM Attack", Attack.class).getResultList();
	}
	
}
