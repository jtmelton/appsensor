package org.owasp.appsensor.storage;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.ResponseListener;
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
 * This is a mongodb implementation of the {@link ResponseStore}.
 * 
 * Implementations of the {@link ResponseListener} interface can register with 
 * this class and be notified when new {@link Response}s are added to the data store 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class MongoResponseStore extends ResponseStore {

	private DBCollection responses;
	
	private Gson gson = new Gson();
	
	private Logger logger;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addResponse(Response response) {
		logger.warn("Security response " + response + " triggered for user: " + response.getUser().getUsername());

		String json = gson.toJson(response);
		
		responses.insert((DBObject)JSON.parse(json));
		
		super.notifyListeners(response);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Response> matches = new ArrayList<Response>();
		
		User user = criteria.getUser();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());

		DBCursor cursor = responses.find();
		
		try {
			while (cursor.hasNext()) {
				DBObject object = cursor.next();
				String json = JSON.serialize(object);
				Response response = gson.fromJson(json, Response.class);

				//check user match if user specified
				boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
				
				//check detection system match if detection systems specified
				boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
						detectionSystemIds.contains(response.getDetectionSystemId()) : true;
				
				boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(response.getTimestamp())) : true;
						
				if (userMatch && detectionSystemMatch && earliestMatch) {
					matches.add(response);
				}
			}
		} finally {
			cursor.close();
		}
		
		
		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		responses = initializeCollection();
		
		if(responses == null) {
			responses = defaultInitialize();
		}
	}
	
	private DBCollection defaultInitialize() {
		DBCollection collection = null;
		
		try {
			Mongo mongoClient = new Mongo();
			DB db = mongoClient.getDB("appsensor_db");
			collection = db.getCollection("responses");
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
