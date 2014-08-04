package org.owasp.appsensor.storage;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.EventListener;
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
 * This is a mongodb implementation of the {@link EventStore}.
 * 
 * Implementations of the {@link EventListener} interface can register with 
 * this class and be notified when new {@link Event}s are added to the data store 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class MongoEventStore extends EventStore {

	private DBCollection events;
	
	private Gson gson = new Gson();
	
	private Logger logger;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		logger.warn("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());
		
		String json = gson.toJson(event);
		
		events.insert((DBObject)JSON.parse(json));
		
		super.notifyListeners(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Event> matches = new ArrayList<Event>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		DBCursor cursor = events.find();
		
		try {
			while (cursor.hasNext()) {
				DBObject object = cursor.next();
				String json = JSON.serialize(object);
				Event event = gson.fromJson(json, Event.class);
				
				// check user match if user specified
				boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;

				// check detection system match if detection systems specified
				boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
						detectionSystemIds.contains(event.getDetectionSystemId()) : true;

				// check detection point match if detection point specified
				boolean detectionPointMatch = (detectionPoint != null) ? 
						detectionPoint.typeMatches(event.getDetectionPoint()) : true;

				boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(event.getTimestamp())): true;

				if (userMatch && detectionSystemMatch && detectionPointMatch&& earliestMatch) {
					matches.add(event);
				}
			}
		} finally {
			cursor.close();
		}

		return matches;
	}
	
	@PostConstruct
	private void initializeMongo() {
		events = initializeCollection();
		
		if(events == null) {
			events = defaultInitialize();
		}
	}
	
	private DBCollection defaultInitialize() {
		DBCollection collection = null;
		
		try {
			Mongo mongoClient = new Mongo();
			DB db = mongoClient.getDB("appsensor_db");
			collection = db.getCollection("events");
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
