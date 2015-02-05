package org.owasp.appsensor.storage.mongo;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.slf4j.Logger;

import com.google.gson.Gson;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.util.JSON;

/**
 * This is a mongodb implementation of the {@link AttackStore}.
 * 
 * Implementations of the {@link AttackListener} interface can register with 
 * this class and be notified when new {@link Attack}s are added to the data store 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class MongoAttackStore extends AttackStore {
	
	private DBCollection attacks;
	
	private Gson gson = new Gson();
	
	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warn("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());
	       
		String json = gson.toJson(attack);
		
		attacks.insert((DBObject)JSON.parse(json));
		
		super.notifyListeners(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Attack> matches = new ArrayList<Attack>();
		
		DBCursor cursor = attacks.find();
		
		try {
			while (cursor.hasNext()) {
				DBObject object = cursor.next();
				String json = JSON.serialize(object);
				Attack attack = gson.fromJson(json, Attack.class);
				
				if (isMatchingAttack(criteria, attack)) {
					matches.add(attack);
				}
			}
		} finally {
			cursor.close();
		}
		
		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		attacks = initializeCollection();
		
		if(attacks == null) {
			attacks = defaultInitialize();
		}
	}
	
	private DBCollection defaultInitialize() {
		DBCollection collection = null;
		
		try {
			Mongo mongoClient = new Mongo();
			DB db = mongoClient.getDB("appsensor_db");
			collection = db.getCollection("attacks");
		} catch (UnknownHostException e) {
			if(logger != null) {
				logger.error("Mongo connection could not be made", e);
			}
			e.printStackTrace();
		}
		
		return collection;
	}
	
	/**
	 * Default implementation - override if you want a custom initializer.
	 * 
	 * @return DBCollection you want to write to.
	 */
	public DBCollection initializeCollection() {
		return null;
	}
	
}
