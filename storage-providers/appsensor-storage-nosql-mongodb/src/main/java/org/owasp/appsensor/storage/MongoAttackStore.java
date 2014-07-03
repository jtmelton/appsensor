package org.owasp.appsensor.storage;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.AttackListener;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.util.DateUtils;
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
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		DBCursor cursor = attacks.find();
		
		try {
			while (cursor.hasNext()) {
				DBObject object = cursor.next();
				String json = JSON.serialize(object);
				Attack attack = gson.fromJson(json, Attack.class);
				
				//check user match if user specified
				boolean userMatch = (user != null) ? user.equals(attack.getUser()) : true;
				
				//check detection system match if detection systems specified
				boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
						detectionSystemIds.contains(attack.getDetectionSystemId()) : true;
				
				//check detection point match if detection point specified
				boolean detectionPointMatch = (detectionPoint != null) ? 
						detectionPoint.typeMatches(attack.getDetectionPoint()) : true;
								
				boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(attack.getTimestamp())) : true;
						
						
				if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
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
		try {
			Mongo mongoClient = new Mongo();
			DB db = mongoClient.getDB("appsensor_db");
			attacks = db.getCollection("attacks");
		} catch (UnknownHostException e) {
			if(logger != null) {
				logger.error("Mongo connection could not be made", e);
			}
			e.printStackTrace();
		}
	}
	
}
