package org.owasp.appsensor.storage.mongo;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import com.google.common.base.Preconditions;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.slf4j.Logger;

import com.google.gson.Gson;
import com.mongodb.Block;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
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
	
	private MongoCollection<Document> attacks;
	
	private Gson gson = new Gson();
	
	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warn("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());
	       
		String json = gson.toJson(attack);
		
		attacks.insertOne(Document.parse(String.valueOf(JSON.parse(json))));
		
		super.notifyListeners(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(final SearchCriteria criteria) {
		Preconditions.checkNotNull(criteria, "criteria must be non-null");

		final Collection<Attack> matches = new ArrayList<>();

		Collection<Bson> filters = new ArrayList<>();

		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();


		if (user != null) {
			filters.add(Filters.eq("user.username", user.getUsername()));
		}

		if (detectionSystemIds != null && detectionSystemIds.size() > 0) {
			filters.add(Filters.in("detectionSystem.detectionSystemId", detectionSystemIds));
		}

		if(detectionPoint != null) {
			if(detectionPoint.getCategory() != null) {
				filters.add(Filters.eq("detectionPoint.category", detectionPoint.getCategory()));
			}

			if(detectionPoint.getLabel() != null) {
				filters.add(Filters.eq("detectionPoint.label", detectionPoint.getLabel()));
			}
		}

		FindIterable<Document> iterable = attacks.find(Filters.and(filters));

		iterable.forEach(new Block<Document>() {
			@Override
			public void apply(final Document document) {

				String json = document.toJson();
				Attack attack = gson.fromJson(json, Attack.class);

				if (isMatchingAttack(criteria, attack)) {
					matches.add(attack);
				}
			}
		});

		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		attacks = initializeCollection();
		
		if(attacks == null) {
			attacks = defaultInitialize();
		}
	}
	
	private MongoCollection<Document> defaultInitialize() {
		MongoCollection<Document> collection = null;
		
		try {
			MongoClient mongoClient = new MongoClient();
			MongoDatabase db = mongoClient.getDatabase("appsensor_db");
			collection = db.getCollection("attacks");
		} catch (Exception e) {
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
	public MongoCollection<Document> initializeCollection() {
		return null;
	}
	
}
