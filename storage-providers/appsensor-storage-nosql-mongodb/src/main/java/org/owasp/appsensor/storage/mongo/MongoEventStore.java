package org.owasp.appsensor.storage.mongo;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.inject.Named;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
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
		
		DBCursor cursor = events.find();
		
		try {
			while (cursor.hasNext()) {
				DBObject object = cursor.next();
				String json = JSON.serialize(object);
				Event event = gson.fromJson(json, Event.class);
				
				if (isMatchingEvent(criteria, event)) {
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
