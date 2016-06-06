package org.owasp.appsensor.ui.repository;

import org.owasp.appsensor.ui.entity.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, String> {
	 
	public User findByUsername(String username);
	
}